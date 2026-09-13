// The verdict taxonomy. "Could not check" must never be reported as "invalid", and a
// verifier fault must never be reported as either valid or invalid. Every case below
// is produced by a real change to real state; no cryptographic operation is mocked.
import fs from "node:fs/promises";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import type { Actor } from "@/lib/auth/rbac";
import { resetMasterKeyCache } from "@/lib/crypto/symmetric";
import { prisma } from "@/lib/db";
import { uploadDocument } from "@/lib/documents/service";
import { signDocument } from "@/lib/documents/signing";
import { absolutePath } from "@/lib/documents/storage";
import { verifyDocument, type VerificationResult } from "@/lib/documents/verification";
import { ensureRootCa } from "@/lib/pki/ca";
import { issueCertificate, revokeCertificate } from "@/lib/pki/certificates";
import { seedUsers } from "@/prisma/fixtures";
import { resetDatabase } from "@/tests/helpers/db";
import { ensureMasterKey } from "@/tests/helpers/master-key";

let admin: Actor;
let signer: Actor;
let verifier: Actor;
let certificateId: string;

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

  certificateId = (await issueCertificate({ actor: signer, algorithm: "ECDSA_P256" })).id;
}, 60_000);

beforeEach(async () => {
  await prisma.signature.deleteMany();
  await prisma.documentVersion.deleteMany();
  await prisma.document.deleteMany();
});

async function signedDocument(contents: string, certificate = certificateId) {
  const document = await uploadDocument({
    actor: signer,
    filename: `${Math.random().toString(36).slice(2)}.txt`,
    mimeType: "text/plain",
    bytes: Buffer.from(contents),
  });
  await signDocument({ actor: signer, documentId: document.id, certificateId: certificate });
  const version = await prisma.documentVersion.findFirstOrThrow({
    where: { documentId: document.id },
  });
  return { document, version };
}

function statusOf(result: VerificationResult, id: string) {
  return result.steps.find((step) => step.id === id)?.status;
}

describe("VALID", () => {
  it("is returned only when every step passes", async () => {
    const { document } = await signedDocument("All evidence is present.");
    const result = await verifyDocument(verifier, document.id);

    expect(result.outcome).toBe("VALID");
    expect(result.reason).toBeUndefined();
    expect(result.steps.every((step) => step.status === "PASS" && step.passed)).toBe(true);
  });

  it("allows only optional steps not to pass: a signature without a time-stamp is still VALID", async () => {
    const { document } = await signedDocument("Signed before time-stamping existed.");
    await prisma.signature.updateMany({
      where: { documentVersion: { documentId: document.id } },
      data: { timestampToken: null, timestampedAt: null },
    });

    const result = await verifyDocument(verifier, document.id);
    expect(result.outcome).toBe("VALID");
    const timestamp = result.steps.find((step) => step.id === "timestamp");
    expect(timestamp).toMatchObject({ status: "SKIPPED", optional: true });
    expect(result.explanation).toMatch(/no trusted time-stamp/);
  });
});

describe("UNVERIFIABLE: missing evidence is not evidence of tampering", () => {
  it("reports a missing blob as STORAGE_UNAVAILABLE, never HASH_MISMATCH", async () => {
    const { document, version } = await signedDocument("This blob will disappear.");
    await fs.rm(absolutePath(version.storagePath));

    const result = await verifyDocument(verifier, document.id);

    expect(result.outcome).toBe("UNVERIFIABLE");
    expect(result.reason).toBe("STORAGE_UNAVAILABLE");
    expect(statusOf(result, "recompute-hash")).toBe("UNAVAILABLE");
    expect(statusOf(result, "signature-verification")).toBe("SKIPPED");
    expect(statusOf(result, "hash-comparison")).toBe("SKIPPED");
    // Nothing is marked as a failure: no check found anything wrong.
    expect(result.steps.some((step) => step.status === "FAIL")).toBe(false);
  });

  it("reports an algorithm with no registered provider as UNSUPPORTED_ALGORITHM", async () => {
    const { document } = await signedDocument("Signed under an algorithm this build lacks.");
    await prisma.signature.updateMany({
      where: { documentVersion: { documentId: document.id } },
      data: { algorithm: "UNREGISTERED_ALGORITHM" },
    });

    const result = await verifyDocument(verifier, document.id);

    expect(result.outcome).toBe("UNVERIFIABLE");
    expect(result.reason).toBe("UNSUPPORTED_ALGORITHM");
    expect(statusOf(result, "signature-verification")).toBe("UNAVAILABLE");
  });

  it("does not advance the document lifecycle to VERIFIED", async () => {
    const { document, version } = await signedDocument("Stored, but never verified.");
    await fs.rm(absolutePath(version.storagePath));

    await verifyDocument(verifier, document.id);

    expect((await prisma.document.findUniqueOrThrow({ where: { id: document.id } })).status).toBe(
      "STORED",
    );
  });

  it("is audited with its verdict", async () => {
    const { document, version } = await signedDocument("Audited as unverifiable.");
    await fs.rm(absolutePath(version.storagePath));

    await verifyDocument(verifier, document.id);

    const entry = await prisma.auditLogEntry.findFirstOrThrow({
      where: { action: "DOCUMENT_VERIFIED", targetId: document.id },
      orderBy: { seq: "desc" },
    });
    expect(JSON.parse(entry.metadataJson)).toMatchObject({
      outcome: "UNVERIFIABLE",
      reason: "STORAGE_UNAVAILABLE",
    });
  });
});

describe("INVALID outranks UNVERIFIABLE", () => {
  it("still reports a revoked certificate when the blob is unreadable", async () => {
    const certificate = await issueCertificate({ actor: signer, algorithm: "ECDSA_P256" });
    const { document, version } = await signedDocument("Revoked and unreadable.", certificate.id);
    await fs.rm(absolutePath(version.storagePath));
    await revokeCertificate({ actor: admin, certificateId: certificate.id, reason: "keyCompromise" });

    const result = await verifyDocument(verifier, document.id);

    expect(result.outcome).toBe("INVALID");
    expect(result.reason).toBe("CERTIFICATE_REVOKED");
  });
});

describe("ERROR: a verifier fault supports no conclusion", () => {
  const originalKeyPath = process.env.MASTER_KEY_PATH;

  afterEach(() => {
    process.env.MASTER_KEY_PATH = originalKeyPath;
    resetMasterKeyCache();
  });

  it("reports INTERNAL_ERROR when the storage key is gone, without leaking its location", async () => {
    const { document } = await signedDocument("The verifier is about to lose its key.");
    process.env.MASTER_KEY_PATH = `${originalKeyPath}.missing`;
    resetMasterKeyCache();

    const result = await verifyDocument(verifier, document.id);

    expect(result.outcome).toBe("ERROR");
    expect(result.reason).toBe("INTERNAL_ERROR");
    expect(JSON.stringify(result)).not.toContain("master.key");
    expect((await prisma.document.findUniqueOrThrow({ where: { id: document.id } })).status).toBe(
      "STORED",
    );
  });
});
