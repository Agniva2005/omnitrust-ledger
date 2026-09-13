// Timestamp-aware verification: a document signed while its certificate was valid is not
// automatically invalidated by what happens to the certificate later, and a time-stamp is
// never accepted as proof of something it does not prove. Every case uses real signatures,
// real RFC 3161 tokens from the local authority, and real CA-signed CRLs.
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import type { Actor } from "@/lib/auth/rbac";
import { sha256 } from "@/lib/crypto/hash";
import { prisma } from "@/lib/db";
import { uploadDocument } from "@/lib/documents/service";
import { signDocument } from "@/lib/documents/signing";
import { verifyDocument, type VerificationResult } from "@/lib/documents/verification";
import { ensureRootCa } from "@/lib/pki/ca";
import { issueCertificate, revokeCertificate } from "@/lib/pki/certificates";
import { issueCrl } from "@/lib/pki/crl";
import { TSA_ACCURACY_MS, issueTimestampToken } from "@/lib/pki/tsa";
import { seedUsers } from "@/prisma/fixtures";
import { resetDatabase } from "@/tests/helpers/db";
import { ensureMasterKey } from "@/tests/helpers/master-key";

let admin: Actor;
let signer: Actor;
let verifier: Actor;

beforeAll(async () => {
  ensureMasterKey();
  await resetDatabase();
  await seedUsers();
  await ensureRootCa();
  const users = await prisma.user.findMany();
  const actorFor = (email: string, role: Actor["role"]): Actor => ({
    userId: users.find((user) => user.email === email)!.id,
    email,
    role,
  });
  admin = actorFor("admin@demo", "ADMIN");
  signer = actorFor("signer@demo", "SIGNER");
  verifier = actorFor("verifier@demo", "VERIFIER");
}, 60_000);

beforeEach(async () => {
  await prisma.signature.deleteMany();
  await prisma.documentVersion.deleteMany();
  await prisma.document.deleteMany();
});

/** A signature provably predates an event only once the time-stamp's accuracy window has passed. */
const pastAccuracyWindow = () => new Promise((resolve) => setTimeout(resolve, TSA_ACCURACY_MS + 1100));

async function certificateValidFromAnHourAgo() {
  return issueCertificate({
    actor: signer,
    algorithm: "ECDSA_P256",
    notBefore: new Date(Date.now() - 3_600_000),
    notAfter: new Date(Date.now() + 86_400_000),
  });
}

async function signedDocument(certificateId: string, contents = `contract ${Math.random()}`) {
  const document = await uploadDocument({
    actor: signer,
    filename: `${Math.random().toString(36).slice(2)}.txt`,
    mimeType: "text/plain",
    bytes: Buffer.from(contents),
  });
  await signDocument({ actor: signer, documentId: document.id, certificateId });
  const signature = await prisma.signature.findFirstOrThrow({
    where: { documentVersion: { documentId: document.id } },
  });
  return { document, signature };
}

const statusOf = (result: VerificationResult, id: string) =>
  result.steps.find((step) => step.id === id)?.status;

describe("revocation after a time-stamped signature", () => {
  it("keeps the signature VALID when the certificate is revoked for affiliationChanged, and says why", async () => {
    const certificate = await certificateValidFromAnHourAgo();
    const { document } = await signedDocument(certificate.id);
    await pastAccuracyWindow();
    await revokeCertificate({ actor: admin, certificateId: certificate.id, reason: "affiliationChanged" });

    const result = await verifyDocument(verifier, document.id);

    expect(result.outcome).toBe("VALID");
    expect(result.trust.trustedTime).not.toBeNull();
    expect(result.trust.revocation?.reason).toBe("affiliationChanged");
    expect(result.trust.revocationDecision).toBe("SIGNED_BEFORE_REVOCATION");
    expect(statusOf(result, "revocation")).toBe("PASS");
    expect(result.explanation).toContain("affiliationChanged");
    expect(result.explanation).toMatch(/remains valid/);
  }, 20_000);

  it("is INVALID when the key is reported compromised with no invalidity date, however early the signature", async () => {
    const certificate = await certificateValidFromAnHourAgo();
    const { document } = await signedDocument(certificate.id);
    await pastAccuracyWindow();
    await revokeCertificate({ actor: admin, certificateId: certificate.id, reason: "keyCompromise" });

    const result = await verifyDocument(verifier, document.id);

    expect(result.outcome).toBe("INVALID");
    expect(result.reason).toBe("CERTIFICATE_REVOKED");
    expect(result.trust.revocationDecision).toBe("COMPROMISE_TIME_UNKNOWN");
  }, 20_000);

  it("keeps the signature VALID when it provably predates the recorded compromise", async () => {
    const certificate = await certificateValidFromAnHourAgo();
    const { document } = await signedDocument(certificate.id);
    await pastAccuracyWindow();
    await revokeCertificate({
      actor: admin,
      certificateId: certificate.id,
      reason: "keyCompromise",
      invalidityDate: new Date(),
    });

    const result = await verifyDocument(verifier, document.id);

    expect(result.outcome).toBe("VALID");
    expect(result.trust.revocationDecision).toBe("SIGNED_BEFORE_COMPROMISE");
  }, 20_000);

  it("is INVALID when the recorded compromise precedes the signature", async () => {
    const certificate = await certificateValidFromAnHourAgo();
    const { document } = await signedDocument(certificate.id);
    await revokeCertificate({
      actor: admin,
      certificateId: certificate.id,
      reason: "keyCompromise",
      invalidityDate: new Date(Date.now() - 1_800_000),
    });

    const result = await verifyDocument(verifier, document.id);

    expect(result.outcome).toBe("INVALID");
    expect(result.reason).toBe("CERTIFICATE_REVOKED");
    expect(result.trust.revocationDecision).toBe("SIGNED_AFTER_COMPROMISE");
  });
});

describe("a time-stamp proves only what it proves", () => {
  it("does not let a time-stamp issued after the revocation rescue the signature", async () => {
    const certificate = await certificateValidFromAnHourAgo();
    const { document, signature } = await signedDocument(certificate.id);
    await revokeCertificate({ actor: admin, certificateId: certificate.id, reason: "superseded" });
    await pastAccuracyWindow();

    // A genuine token from the real authority over the same signature value, but obtained later.
    const late = await issueTimestampToken({ imprint: sha256(signature.signatureBytes) });
    await prisma.signature.update({
      where: { id: signature.id },
      data: { timestampToken: new Uint8Array(late.token), timestampedAt: late.genTime },
    });

    const result = await verifyDocument(verifier, document.id);

    expect(statusOf(result, "timestamp")).toBe("PASS");
    expect(result.outcome).toBe("INVALID");
    expect(result.reason).toBe("CERTIFICATE_REVOKED");
    expect(result.trust.revocationDecision).toBe("SIGNED_AFTER_REVOCATION");
  }, 20_000);

  it("refuses a token that belongs to a different signature", async () => {
    const certificate = await certificateValidFromAnHourAgo();
    const first = await signedDocument(certificate.id);
    const second = await signedDocument(certificate.id);
    await prisma.signature.update({
      where: { id: first.signature.id },
      data: { timestampToken: second.signature.timestampToken },
    });

    const result = await verifyDocument(verifier, first.document.id);

    expect(result.outcome).toBe("INVALID");
    expect(result.reason).toBe("TIMESTAMP_INVALID");
    // The signature and the document themselves are fine.
    expect(statusOf(result, "signature-verification")).toBe("PASS");
    expect(statusOf(result, "hash-comparison")).toBe("PASS");
  });

  it("refuses a corrupted token", async () => {
    const certificate = await certificateValidFromAnHourAgo();
    const { document, signature } = await signedDocument(certificate.id);
    const corrupted = Buffer.from(signature.timestampToken!);
    corrupted[corrupted.length - 1] ^= 0x01;
    await prisma.signature.update({
      where: { id: signature.id },
      data: { timestampToken: new Uint8Array(corrupted) },
    });

    const result = await verifyDocument(verifier, document.id);

    expect(result.outcome).toBe("INVALID");
    expect(result.reason).toBe("TIMESTAMP_INVALID");
  });
});

describe("without a trusted time-stamp", () => {
  it("is UNVERIFIABLE, not INVALID, when the certificate is later revoked (REVOKED_NO_POE)", async () => {
    const certificate = await certificateValidFromAnHourAgo();
    const { document, signature } = await signedDocument(certificate.id);
    // As if the Time-Stamp Authority had been unavailable at signing.
    await prisma.signature.update({
      where: { id: signature.id },
      data: { timestampToken: null, timestampedAt: null },
    });
    await revokeCertificate({ actor: admin, certificateId: certificate.id, reason: "affiliationChanged" });

    const result = await verifyDocument(verifier, document.id);

    expect(result.outcome).toBe("UNVERIFIABLE");
    expect(result.reason).toBe("REVOKED_NO_PROOF_OF_EXISTENCE");
    expect(statusOf(result, "revocation")).toBe("UNAVAILABLE");
    expect(result.explanation).toMatch(/no trusted time-stamp/);
  });
});

describe("revocation evidence that cannot be trusted", () => {
  it("is UNVERIFIABLE when the CA's revocation list has been tampered with", async () => {
    const certificate = await certificateValidFromAnHourAgo();
    const { document } = await signedDocument(certificate.id);
    const list = await issueCrl();
    const altered = Buffer.from(list.der);
    altered[altered.length - 1] ^= 0x01;
    await prisma.revocationList.update({ where: { id: list.id }, data: { der: new Uint8Array(altered) } });

    const result = await verifyDocument(verifier, document.id);

    expect(result.outcome).toBe("UNVERIFIABLE");
    expect(result.reason).toBe("REVOCATION_STATUS_UNAVAILABLE");
    expect(statusOf(result, "revocation")).toBe("UNAVAILABLE");
    // It is not a finding against the document.
    expect(statusOf(result, "signature-verification")).toBe("PASS");
  });
});
