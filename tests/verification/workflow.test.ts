// Phase 6 DoD: every failure below is produced by a real alteration to real data and
// verified with real cryptography. Nothing in this file mocks a crypto operation.
import fs from "node:fs/promises";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { AuthorizationError, type Actor } from "@/lib/auth/rbac";
import { orchestrator } from "@/lib/crypto/orchestrator";
import { encrypt } from "@/lib/crypto/symmetric";
import { ALGORITHMS, type Algorithm } from "@/lib/crypto/types";
import { prisma } from "@/lib/db";
import { uploadDocument } from "@/lib/documents/service";
import { absolutePath, writeBlob } from "@/lib/documents/storage";
import { signDocument } from "@/lib/documents/signing";
import { DocumentNotSignedError, verifyDocument } from "@/lib/documents/verification";
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

describe("the happy path", () => {
  it.each(ALGORITHMS)("returns AUTHENTIC for an untouched %s-signed document", async (algorithm) => {
    const document = await uploadAndSign(algorithm);
    const result = await verifyDocument(verifier, document.id);

    expect(result.outcome).toBe("AUTHENTIC");
    expect(result.reason).toBeUndefined();
    expect(result.steps.every((step) => step.passed)).toBe(true);
  });

  it("executes all eight numbered steps in order", async () => {
    const document = await uploadAndSign("ED25519");
    const result = await verifyDocument(verifier, document.id);

    const numbered = result.steps
      .map((step) => step.step)
      .filter((step) => /^[1-8]\. /.test(step))
      .map((step) => Number(step[0]));

    expect(numbered).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
  });

  it("advances the lifecycle to VERIFIED (Figure 4)", async () => {
    const document = await uploadAndSign("RSA");
    expect(document.status).toBe("HASHED");

    await verifyDocument(verifier, document.id);
    expect(
      (await prisma.document.findUniqueOrThrow({ where: { id: document.id } })).status,
    ).toBe("VERIFIED");
  });

  it("is repeatable and still AUTHENTIC the second time", async () => {
    const document = await uploadAndSign("ECDSA_P256");
    expect((await verifyDocument(verifier, document.id)).outcome).toBe("AUTHENTIC");
    expect((await verifyDocument(verifier, document.id)).outcome).toBe("AUTHENTIC");
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

    const step6 = result.steps.find((step) => step.step.startsWith("6."));
    expect(step6?.passed).toBe(false);
    expect(step6?.detail).toMatch(/AES-256-GCM integrity check/);
  });

  it("reports HASH_MISMATCH when different plaintext is validly re-encrypted", async () => {
    // The stronger case: an attacker who also holds the storage key. The blob decrypts
    // cleanly, so the AES-GCM tag passes and the hash comparison in step 8 is what
    // actually catches the substitution.
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

    // Step 6 succeeded -- the bytes decrypted -- and step 8 is the one that failed.
    expect(result.steps.find((step) => step.step.startsWith("6."))?.passed).toBe(true);
    const step8 = result.steps.find((step) => step.step.startsWith("8."));
    expect(step8?.passed).toBe(false);
    expect(step8?.detail).toContain(version.hash);
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
  it("reports CERTIFICATE_EXPIRED", async () => {
    const certificate = await issueCertificate({
      actor: signer,
      algorithm: "ED25519",
      notBefore: new Date(Date.now() - 60_000),
      notAfter: new Date(Date.now() + 4_000),
    });

    const document = await uploadAndSign("ED25519", "Signed just before expiry.", certificate.id);

    // Evaluate after the window closes, rather than sleeping.
    const result = await verifyDocument(verifier, document.id, {
      at: new Date(Date.now() + 60_000),
    });

    expect(result.outcome).toBe("INVALID");
    expect(result.reason).toBe("CERTIFICATE_EXPIRED");
    expect(
      result.steps.find((step) => step.step.includes("Within validity period"))?.passed,
    ).toBe(false);
  });

  it("still verifies the cryptography correctly while reporting the expiry", async () => {
    const certificate = await issueCertificate({
      actor: signer,
      algorithm: "RSA",
      notBefore: new Date(Date.now() - 60_000),
      notAfter: new Date(Date.now() + 4_000),
    });
    const document = await uploadAndSign("RSA", "Expired but untampered.", certificate.id);

    const result = await verifyDocument(verifier, document.id, {
      at: new Date(Date.now() + 60_000),
    });

    expect(result.reason).toBe("CERTIFICATE_EXPIRED");
    // The signature itself is fine; only the certificate's window has closed.
    expect(result.steps.find((step) => step.step.startsWith("7."))?.passed).toBe(true);
    expect(result.steps.find((step) => step.step.startsWith("8."))?.passed).toBe(true);
  });
});

describe("Phase 6 case 3: a revoked certificate", () => {
  it("verifies before revocation and reports CERTIFICATE_REVOKED afterwards", async () => {
    const certificate = await issueCertificate({ actor: signer, algorithm: "ECDSA_P256" });
    const document = await uploadAndSign("ECDSA_P256", "Signed, then revoked.", certificate.id);

    expect((await verifyDocument(verifier, document.id)).outcome).toBe("AUTHENTIC");

    await revokeCertificate({
      actor: admin,
      certificateId: certificate.id,
      reason: "Key compromise (test)",
    });

    const result = await verifyDocument(verifier, document.id);
    expect(result.outcome).toBe("INVALID");
    expect(result.reason).toBe("CERTIFICATE_REVOKED");

    const revocationStep = result.steps.find((step) => step.step.includes("Not revoked"));
    expect(revocationStep?.passed).toBe(false);
    expect(revocationStep?.detail).toContain("Key compromise (test)");
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
    expect(result.steps.find((step) => step.step.startsWith("7."))?.passed).toBe(false);
    // The document itself was not touched, so the hash comparison still passes.
    expect(result.steps.find((step) => step.step.startsWith("8."))?.passed).toBe(true);
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
    "a %s-signed document fails when the certificate carries a different algorithm's key",
    async (algorithm) => {
      const document = await uploadAndSign(algorithm, `Key substitution test (${algorithm}).`);
      expect((await verifyDocument(verifier, document.id)).outcome).toBe("AUTHENTIC");

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
      expect(result.reason).toBe("SIGNATURE_INVALID");
      expect(result.steps.find((step) => step.step.startsWith("7."))?.passed).toBe(false);
    },
  );

  it("does not throw when the substituted key is structurally wrong for the algorithm", async () => {
    // Ed25519 keys are 32 bytes and RSA keys are not: the provider is handed something
    // it cannot use at all. That must surface as INVALID, not as a crash.
    const document = await uploadAndSign("RSA", "Structurally incompatible key.");
    const signature = await prisma.signature.findFirstOrThrow({
      where: { documentVersion: { documentId: document.id } },
    });
    await prisma.signature.update({
      where: { id: signature.id },
      data: { certificateId: certificates.ED25519.id },
    });

    const result = await verifyDocument(verifier, document.id);
    expect(result.outcome).toBe("INVALID");
    expect(result.reason).toBe("SIGNATURE_INVALID");
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
    // Both step 7 and step 8 fail; the reported reason is the more precise one.
    expect(result.steps.find((step) => step.step.startsWith("7."))?.passed).toBe(false);
    expect(result.steps.find((step) => step.step.startsWith("8."))?.passed).toBe(false);
    expect(result.reason).toBe("HASH_MISMATCH");
  });

  it("prefers a certificate failure over a content failure", async () => {
    const certificate = await issueCertificate({ actor: signer, algorithm: "RSA" });
    const document = await uploadAndSign("RSA", "Both problems at once.", certificate.id);

    const version = await prisma.documentVersion.findFirstOrThrow({
      where: { documentId: document.id },
    });
    await writeBlob(version.storagePath, Buffer.from("Tampered as well."));
    await revokeCertificate({ actor: admin, certificateId: certificate.id });

    const result = await verifyDocument(verifier, document.id);
    expect(result.reason).toBe("CERTIFICATE_REVOKED");
    expect(result.steps.find((step) => step.step.startsWith("8."))?.passed).toBe(false);
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
    expect((await verifyDocument(verifier, document.id)).outcome).toBe("AUTHENTIC");
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
    // because step 5 extracts the key from the certificate.
    const signature = await prisma.signature.findFirstOrThrow({
      where: { documentVersion: { documentId: document.id } },
      include: { certificate: true },
    });
    const foreign = await orchestrator.generateKeyPair("ED25519");
    await prisma.keyPair.update({
      where: { id: signature.certificate.keyPairId },
      data: { publicKeyPem: foreign.publicKeyPem },
    });

    expect((await verifyDocument(verifier, document.id)).outcome).toBe("AUTHENTIC");
  });
});
