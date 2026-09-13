// Phase 6 DoD, carried forward: every failure below is produced by a real alteration to
// real data and verified with real cryptography. Nothing in this file mocks a crypto
// operation. Time-aware revocation cases live in timestamp-aware.test.ts.
import fs from "node:fs/promises";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { AuthorizationError, type Actor } from "@/lib/auth/rbac";
import { ALGORITHMS, orchestrator, type Algorithm } from "@/lib/crypto/orchestrator";
import { encrypt } from "@/lib/crypto/symmetric";
import { prisma } from "@/lib/db";
import { uploadDocument } from "@/lib/documents/service";
import { absolutePath, writeBlob } from "@/lib/documents/storage";
import { signDocument } from "@/lib/documents/signing";
import {
  DocumentNotSignedError,
  verifyDocument,
  type VerificationResult,
} from "@/lib/documents/verification";
import { ensureRootCa } from "@/lib/pki/ca";
import { issueCertificate, revokeCertificate } from "@/lib/pki/certificates";
import { seedUsers } from "@/prisma/fixtures";
import { resetDatabase } from "@/tests/helpers/db";
import { ensureMasterKey } from "@/tests/helpers/master-key";

let admin: Actor;
let signer: Actor;
let verifier: Actor;
let viewer: Actor;
const certificates = {} as Record<Algorithm, Awaited<ReturnType<typeof issueCertificate>>>;

beforeAll(async () => {
  ensureMasterKey();
  await resetDatabase();
  await seedUsers();
  await ensureRootCa();

  const users = await prisma.user.findMany();
  const id = (email: string) => users.find((user) => user.email === email)!.id;
  admin = { userId: id("admin@demo"), email: "admin@demo", role: "ADMIN" };
  signer = { userId: id("signer@demo"), email: "signer@demo", role: "SIGNER" };
  verifier = { userId: id("verifier@demo"), email: "verifier@demo", role: "VERIFIER" };
  viewer = { userId: id("viewer@demo"), email: "viewer@demo", role: "VIEWER" };

  for (const algorithm of ALGORITHMS) {
    certificates[algorithm] = await issueCertificate({ actor: signer, algorithm });
  }
}, 120_000);

beforeEach(async () => {
  await prisma.signature.deleteMany();
  await prisma.documentVersion.deleteMany();
  await prisma.document.deleteMany();
});

async function uploadAndSign(
  algorithm: Algorithm,
  contents = "A document that will be verified.",
  certificateId = certificates[algorithm].id,
) {
  const document = await uploadDocument({
    actor: signer,
    filename: `${algorithm}-${Math.random().toString(36).slice(2)}.txt`,
    mimeType: "text/plain",
    bytes: Buffer.from(contents),
  });
  await signDocument({ actor: signer, documentId: document.id, certificateId });
  return document;
}

function stepOf(result: VerificationResult, id: string) {
  return result.steps.find((step) => step.id === id);
}

const statusOf = (result: VerificationResult, id: string) => stepOf(result, id)?.status;

describe("the happy path", () => {
  it.each(ALGORITHMS)("returns VALID for an untouched %s-signed document", async (algorithm) => {
    const document = await uploadAndSign(algorithm);
    const result = await verifyDocument(verifier, document.id);

    expect(result.outcome).toBe("VALID");
    expect(result.reason).toBeUndefined();
    expect(result.steps.every((step) => step.passed)).toBe(true);
    expect(result.trust.trustedTime).not.toBeNull();
  });

  it("executes all ten numbered steps in order", async () => {
    const document = await uploadAndSign("ED25519");
    const result = await verifyDocument(verifier, document.id);

    const numbered = result.steps
      .map((step) => /^(\d+)\. /.exec(step.step)?.[1])
      .filter((value): value is string => value !== undefined)
      .map(Number);

    expect(numbered).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
  });

  it("advances the lifecycle to VERIFIED (Figure 4)", async () => {
    const document = await uploadAndSign("RSA");
    expect(document.status).toBe("HASHED");

    await verifyDocument(verifier, document.id);
    expect(
      (await prisma.document.findUniqueOrThrow({ where: { id: document.id } })).status,
    ).toBe("VERIFIED");
  });

  it("is repeatable and still VALID the second time", async () => {
    const document = await uploadAndSign("ECDSA_P256");
    expect((await verifyDocument(verifier, document.id)).outcome).toBe("VALID");
    expect((await verifyDocument(verifier, document.id)).outcome).toBe("VALID");
  });

  it("explains a valid result in words", async () => {
    const document = await uploadAndSign("ECDSA_P256");
    const result = await verifyDocument(verifier, document.id);
    expect(result.explanation).toMatch(/unchanged/);
    expect(result.explanation).toMatch(/trusted time-stamp/);
  });
});

describe("Phase 6 case 1: a flipped byte in the stored blob", () => {
  it("reports HASH_MISMATCH when the ciphertext on disk is altered", async () => {
    const document = await uploadAndSign("ED25519", "Bytes that will be flipped.");
    const version = await prisma.documentVersion.findFirstOrThrow({
      where: { documentId: document.id },
    });

    const target = absolutePath(version.storagePath);
    const stored = await fs.readFile(target);
    stored[stored.length - 1] ^= 0x01;
    await fs.writeFile(target, stored);

    const result = await verifyDocument(verifier, document.id);
    expect(result.outcome).toBe("INVALID");
    expect(result.reason).toBe("HASH_MISMATCH");

    const recompute = stepOf(result, "recompute-hash");
    expect(recompute?.passed).toBe(false);
    expect(recompute?.detail).toMatch(/AES-256-GCM integrity check/);
  });

  it("reports HASH_MISMATCH when different plaintext is validly re-encrypted", async () => {
    // The stronger case: an attacker who also holds the storage key. The blob decrypts
    // cleanly, so the AES-GCM tag passes and the hash comparison is what actually catches
    // the substitution.
    const document = await uploadAndSign("RSA", "The agreed price is 1,000.");
    const version = await prisma.documentVersion.findFirstOrThrow({
      where: { documentId: document.id },
    });

    await fs.writeFile(
      absolutePath(version.storagePath),
      encrypt(Buffer.from("The agreed price is 9,000.")),
    );

    const result = await verifyDocument(verifier, document.id);
    expect(result.outcome).toBe("INVALID");
    expect(result.reason).toBe("HASH_MISMATCH");
    expect(result.explanation).toMatch(/content differs/);

    expect(statusOf(result, "recompute-hash")).toBe("PASS");
    const comparison = stepOf(result, "hash-comparison");
    expect(comparison?.passed).toBe(false);
    expect(comparison?.detail).toContain(version.hash);
  });

  it("reports HASH_MISMATCH when a single character of the plaintext changes", async () => {
    const document = await uploadAndSign("ECDSA_P256", "Clause 4 applies.");
    const version = await prisma.documentVersion.findFirstOrThrow({
      where: { documentId: document.id },
    });

    await writeBlob(version.storagePath, Buffer.from("Clause 5 applies."));

    const result = await verifyDocument(verifier, document.id);
    expect(result.reason).toBe("HASH_MISMATCH");
  });
});

describe("Phase 6 case 2: an expired certificate", () => {
  async function expiringCertificate(algorithm: Algorithm) {
    return issueCertificate({
      actor: signer,
      algorithm,
      notBefore: new Date(Date.now() - 60_000),
      notAfter: new Date(Date.now() + 4_000),
    });
  }

  it("leaves a signature VALID when a trusted time-stamp shows it was made while the certificate was valid", async () => {
    const certificate = await expiringCertificate("ED25519");
    const document = await uploadAndSign("ED25519", "Signed just before expiry.", certificate.id);

    // Verify after the window closes, rather than sleeping.
    const result = await verifyDocument(verifier, document.id, { at: new Date(Date.now() + 60_000) });

    expect(result.outcome).toBe("VALID");
    expect(result.trust.certificateExpiredSince).toBe(true);
    expect(result.explanation).toMatch(/since expired/);
  });

  it("reports EXPIRED_NO_PROOF_OF_EXISTENCE, not INVALID, when there is no time-stamp", async () => {
    const certificate = await expiringCertificate("RSA");
    const document = await uploadAndSign("RSA", "Expired and never time-stamped.", certificate.id);
    await prisma.signature.updateMany({
      where: { documentVersion: { documentId: document.id } },
      data: { timestampToken: null, timestampedAt: null },
    });

    const result = await verifyDocument(verifier, document.id, { at: new Date(Date.now() + 60_000) });

    expect(result.outcome).toBe("UNVERIFIABLE");
    expect(result.reason).toBe("EXPIRED_NO_PROOF_OF_EXISTENCE");
    expect(statusOf(result, "certificate-validity")).toBe("UNAVAILABLE");
    // The cryptography itself is fine; only the time question is open.
    expect(statusOf(result, "signature-verification")).toBe("PASS");
    expect(statusOf(result, "hash-comparison")).toBe("PASS");
  });
});

describe("Phase 6 case 3: a revoked certificate", () => {
  it("verifies before revocation and is INVALID after a key compromise with no invalidity date", async () => {
    const certificate = await issueCertificate({ actor: signer, algorithm: "ECDSA_P256" });
    const document = await uploadAndSign("ECDSA_P256", "Signed, then revoked.", certificate.id);

    expect((await verifyDocument(verifier, document.id)).outcome).toBe("VALID");

    await revokeCertificate({
      actor: admin,
      certificateId: certificate.id,
      reason: "keyCompromise",
      comment: "Key compromise (test)",
    });

    const result = await verifyDocument(verifier, document.id);
    expect(result.outcome).toBe("INVALID");
    expect(result.reason).toBe("CERTIFICATE_REVOKED");
    expect(result.trust.revocationDecision).toBe("COMPROMISE_TIME_UNKNOWN");

    const revocation = stepOf(result, "revocation");
    expect(revocation?.status).toBe("FAIL");
    expect(revocation?.detail).toContain("keyCompromise");
    expect(revocation?.detail).toMatch(/CRL #\d+/);
  });
});

describe("Phase 6 case 4: corrupted signature bytes", () => {
  it.each(ALGORITHMS)("reports SIGNATURE_INVALID for a flipped bit in a %s signature", async (algorithm) => {
    const document = await uploadAndSign(algorithm, `Signature will be corrupted (${algorithm}).`);

    const signature = await prisma.signature.findFirstOrThrow({
      where: { documentVersion: { documentId: document.id } },
    });
    const corrupted = Buffer.from(signature.signatureBytes);
    corrupted[corrupted.length - 1] ^= 0x01;
    await prisma.signature.update({
      where: { id: signature.id },
      data: { signatureBytes: new Uint8Array(corrupted) },
    });

    const result = await verifyDocument(verifier, document.id);
    expect(result.outcome).toBe("INVALID");
    expect(result.reason).toBe("SIGNATURE_INVALID");
    expect(statusOf(result, "signature-verification")).toBe("FAIL");
    // The time-stamp was over the original signature value, so it no longer matches either.
    expect(statusOf(result, "timestamp")).toBe("FAIL");
    // The document itself was not touched, so the hash comparison still passes.
    expect(statusOf(result, "hash-comparison")).toBe("PASS");
  });

  it("reports SIGNATURE_INVALID for a signature made over a different document", async () => {
    const first = await uploadAndSign("ED25519", "Document A contents.");
    const second = await uploadAndSign("ED25519", "Document B contents.");

    const signatureOfB = await prisma.signature.findFirstOrThrow({
      where: { documentVersion: { documentId: second.id } },
    });
    const signatureOfA = await prisma.signature.findFirstOrThrow({
      where: { documentVersion: { documentId: first.id } },
    });

    await prisma.signature.update({
      where: { id: signatureOfA.id },
      data: { signatureBytes: signatureOfB.signatureBytes },
    });

    expect((await verifyDocument(verifier, first.id)).reason).toBe("SIGNATURE_INVALID");
  });
});

describe("Phase 6 case 5: substituting another algorithm's public key", () => {
  it.each(ALGORITHMS)(
    "a %s-signed document pointed at another algorithm's certificate is refused as ALGORITHM_MISMATCH",
    async (algorithm) => {
      const document = await uploadAndSign(algorithm, `Key substitution test (${algorithm}).`);
      expect((await verifyDocument(verifier, document.id)).outcome).toBe("VALID");

      const other = ALGORITHMS.find((candidate) => candidate !== algorithm)!;
      const signature = await prisma.signature.findFirstOrThrow({
        where: { documentVersion: { documentId: document.id } },
      });

      // Point the signature at a certificate carrying the other algorithm's public key,
      // while leaving the signature's own algorithm as-is.
      await prisma.signature.update({
        where: { id: signature.id },
        data: { certificateId: certificates[other].id },
      });

      const result = await verifyDocument(verifier, document.id);
      expect(result.outcome).toBe("INVALID");
      expect(result.reason).toBe("ALGORITHM_MISMATCH");
      expect(statusOf(result, "public-key")).toBe("FAIL");
      // No cryptographic operation is attempted with a key of the wrong algorithm.
      expect(statusOf(result, "signature-verification")).toBe("SKIPPED");
    },
  );

  it("is not fooled by relabelling the substituted certificate's database row to match", async () => {
    const document = await uploadAndSign("RSA", "Relabelled certificate.");
    const impostor = await issueCertificate({ actor: signer, algorithm: "ED25519" });
    await prisma.certificate.update({ where: { id: impostor.id }, data: { algorithm: "RSA" } });

    const signature = await prisma.signature.findFirstOrThrow({
      where: { documentVersion: { documentId: document.id } },
    });
    await prisma.signature.update({
      where: { id: signature.id },
      data: { certificateId: impostor.id },
    });

    const result = await verifyDocument(verifier, document.id);
    expect(result.reason).toBe("ALGORITHM_MISMATCH");
    expect(stepOf(result, "public-key")?.detail).toContain("carries a ED25519 key");
  });

  it("still fails cryptographically when every label is forged to agree", async () => {
    // Signature record, certificate record and key now all say ED25519, but the signature
    // bytes are an RSA signature: consistency passes and the cryptography refuses.
    const document = await uploadAndSign("RSA", "Every label forged.");
    const signature = await prisma.signature.findFirstOrThrow({
      where: { documentVersion: { documentId: document.id } },
    });
    await prisma.signature.update({
      where: { id: signature.id },
      data: { certificateId: certificates.ED25519.id, algorithm: "ED25519" },
    });

    const result = await verifyDocument(verifier, document.id);
    expect(result.outcome).toBe("INVALID");
    expect(result.reason).toBe("SIGNATURE_INVALID");
    expect(statusOf(result, "public-key")).toBe("PASS");
    expect(statusOf(result, "signature-verification")).toBe("FAIL");
  });
});

describe("reason precedence", () => {
  it("prefers HASH_MISMATCH over SIGNATURE_INVALID when the content changed", async () => {
    const document = await uploadAndSign("ED25519", "Original text.");
    const version = await prisma.documentVersion.findFirstOrThrow({
      where: { documentId: document.id },
    });
    await writeBlob(version.storagePath, Buffer.from("Replaced text."));

    const result = await verifyDocument(verifier, document.id);
    // Both the signature and the hash comparison fail; the reported reason is the more precise one.
    expect(statusOf(result, "signature-verification")).toBe("FAIL");
    expect(statusOf(result, "hash-comparison")).toBe("FAIL");
    expect(result.reason).toBe("HASH_MISMATCH");
  });

  it("prefers a certificate failure over a content failure", async () => {
    const certificate = await issueCertificate({ actor: signer, algorithm: "RSA" });
    const document = await uploadAndSign("RSA", "Both problems at once.", certificate.id);

    const version = await prisma.documentVersion.findFirstOrThrow({
      where: { documentId: document.id },
    });
    await writeBlob(version.storagePath, Buffer.from("Tampered as well."));
    await revokeCertificate({ actor: admin, certificateId: certificate.id, reason: "keyCompromise" });

    const result = await verifyDocument(verifier, document.id);
    expect(result.reason).toBe("CERTIFICATE_REVOKED");
    expect(statusOf(result, "hash-comparison")).toBe("FAIL");
  });
});

describe("Section 6: a document with no signature", () => {
  it("raises a distinct not-signed error rather than crashing or reporting INVALID", async () => {
    const document = await uploadDocument({
      actor: signer,
      filename: "unsigned.txt",
      mimeType: "text/plain",
      bytes: Buffer.from("Never signed."),
    });

    await expect(verifyDocument(verifier, document.id)).rejects.toThrow(DocumentNotSignedError);
    await expect(verifyDocument(verifier, document.id)).rejects.toThrow(/not been signed yet/);
  });
});

describe("authorisation", () => {
  it("lets a VERIFIER verify", async () => {
    const document = await uploadAndSign("ED25519");
    expect((await verifyDocument(verifier, document.id)).outcome).toBe("VALID");
  });

  it("refuses a VIEWER", async () => {
    const document = await uploadAndSign("ED25519");
    await expect(verifyDocument(viewer, document.id)).rejects.toThrow(AuthorizationError);
  });
});

describe("independence from the key-pair record", () => {
  it("uses the public key inside the certificate, not the KeyPair row", async () => {
    const document = await uploadAndSign("ED25519", "Certificate is the source of truth.");

    // Corrupt the KeyPair row's copy of the public key. Verification must be unaffected,
    // because the key is extracted from the certificate.
    const signature = await prisma.signature.findFirstOrThrow({
      where: { documentVersion: { documentId: document.id } },
      include: { certificate: true },
    });
    const foreign = await orchestrator.generateKeyPair("ED25519");
    await prisma.keyPair.update({
      where: { id: signature.certificate.keyPairId },
      data: { publicKeyPem: foreign.publicKeyPem },
    });

    expect((await verifyDocument(verifier, document.id)).outcome).toBe("VALID");
  });
});
