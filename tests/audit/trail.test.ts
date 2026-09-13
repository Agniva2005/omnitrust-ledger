// Phase 7 DoD: a realistic sequence of demo actions must produce a coherent audit
// trail, and the integrity check must pass on it.
import { beforeAll, describe, expect, it } from "vitest";
import { verifyAuditChain } from "@/lib/audit/integrity";
import { listAuditEntries } from "@/lib/audit/log";
import type { Actor } from "@/lib/auth/rbac";
import { prisma } from "@/lib/db";
import { uploadDocument } from "@/lib/documents/service";
import { signDocument } from "@/lib/documents/signing";
import { verifyDocument } from "@/lib/documents/verification";
import { writeBlob } from "@/lib/documents/storage";
import { ensureRootCa } from "@/lib/pki/ca";
import { issueCertificate, revokeCertificate } from "@/lib/pki/certificates";
import { seedUsers } from "@/prisma/fixtures";
import { resetDatabase } from "@/tests/helpers/db";
import { ensureMasterKey } from "@/tests/helpers/master-key";

let entries: Awaited<ReturnType<typeof listAuditEntries>>;
let admin: Actor;
let signer: Actor;

beforeAll(async () => {
  ensureMasterKey();
  await resetDatabase();
  await seedUsers();
  await ensureRootCa();

  const users = await prisma.user.findMany();
  const id = (email: string) => users.find((user) => user.email === email)!.id;
  admin = { userId: id("admin@demo"), email: "admin@demo", role: "ADMIN" };
  signer = { userId: id("signer@demo"), email: "signer@demo", role: "SIGNER" };

  // A walk through the demo: issue, upload, sign, verify (good), tamper, verify (bad),
  // revoke, verify (revoked).
  const certificate = await issueCertificate({ actor: signer, algorithm: "ED25519" });

  const good = await uploadDocument({
    actor: signer,
    filename: "audit-good.txt",
    mimeType: "text/plain",
    bytes: Buffer.from("An untouched document."),
  });
  await signDocument({ actor: signer, documentId: good.id, certificateId: certificate.id });
  await verifyDocument(admin, good.id);

  const tampered = await uploadDocument({
    actor: signer,
    filename: "audit-tampered.txt",
    mimeType: "text/plain",
    bytes: Buffer.from("Original contents."),
  });
  await signDocument({ actor: signer, documentId: tampered.id, certificateId: certificate.id });
  const version = await prisma.documentVersion.findFirstOrThrow({
    where: { documentId: tampered.id },
  });
  await writeBlob(version.storagePath, Buffer.from("Altered contents."));
  await verifyDocument(admin, tampered.id);

  await revokeCertificate({
    actor: admin,
    certificateId: certificate.id,
    // A compromise with no invalidity date invalidates the signature regardless of timing,
    // which keeps this sequence deterministic under timestamp-aware revocation.
    reason: "keyCompromise",
    comment: "Demo revocation",
  });
  await verifyDocument(admin, good.id);

  entries = await listAuditEntries();
}, 120_000);

describe("a realistic demo sequence", () => {
  it("records every security-relevant action Phase 7 lists", async () => {
    const actions = entries.map((entry) => entry.action);
    for (const expected of [
      "CERTIFICATE_ISSUED",
      "KEY_LIFECYCLE_CHANGED",
      "DOCUMENT_UPLOADED",
      "DOCUMENT_SIGNED",
      "DOCUMENT_VERIFIED",
      "CERTIFICATE_REVOKED",
    ]) {
      expect(actions).toContain(expected);
    }
  });

  it("records both verification outcomes with their reasons", async () => {
    const verifications = entries
      .filter((entry) => entry.action === "DOCUMENT_VERIFIED")
      .map((entry) => JSON.parse(entry.metadataJson) as { outcome: string; reason: string | null });

    expect(verifications).toHaveLength(3);
    expect(verifications.filter((entry) => entry.outcome === "VALID")).toHaveLength(1);
    expect(verifications.filter((entry) => entry.outcome === "INVALID")).toHaveLength(2);
    expect(verifications.map((entry) => entry.reason)).toContain("HASH_MISMATCH");
    expect(verifications.map((entry) => entry.reason)).toContain("CERTIFICATE_REVOKED");
  });

  it("attributes each action to the user who performed it", async () => {
    const signed = entries.find((entry) => entry.action === "DOCUMENT_SIGNED");
    expect(signed?.actor?.email).toBe("signer@demo");

    const revoked = entries.find((entry) => entry.action === "CERTIFICATE_REVOKED");
    expect(revoked?.actor?.email).toBe("admin@demo");
  });

  it("records key lifecycle transitions in both directions", async () => {
    const transitions = entries
      .filter((entry) => entry.action === "KEY_LIFECYCLE_CHANGED")
      .map((entry) => JSON.parse(entry.metadataJson) as { from: string; to: string });

    expect(transitions).toContainEqual(expect.objectContaining({ from: "GENERATED", to: "ACTIVE" }));
    expect(transitions).toContainEqual(expect.objectContaining({ from: "ACTIVE", to: "REVOKED" }));
  });

  it("never writes a password or private key into the log", async () => {
    const serialised = JSON.stringify(entries);
    expect(serialised).not.toContain("demo1234");
    expect(serialised).not.toContain("PRIVATE KEY");
    expect(serialised).not.toMatch(/\$2[aby]\$/); // a bcrypt hash
  });

  it("leaves the chain intact across the whole sequence", async () => {
    const result = await verifyAuditChain();
    expect(result.valid).toBe(true);
    expect(result.entriesChecked).toBe(entries.length);
    expect(result.entriesChecked).toBeGreaterThan(10);
  });

  it("numbers entries contiguously from 1 in the order they happened", async () => {
    const ascending = [...entries].reverse();
    expect(ascending.map((entry) => entry.seq)).toEqual(
      ascending.map((_, index) => index + 1),
    );
  });
});
