// The dashboard shows counts and records read from the database, so this test builds a known
// state through the real services and checks each figure against it.
import { beforeAll, describe, expect, it } from "vitest";
import type { Actor } from "@/lib/auth/rbac";
import { orchestrator } from "@/lib/crypto/orchestrator";
import { prisma } from "@/lib/db";
import { systemOverview } from "@/lib/dashboard/overview";
import { uploadDocument } from "@/lib/documents/service";
import { signDocument } from "@/lib/documents/signing";
import { verifyDocument } from "@/lib/documents/verification";
import { ensureRootCa } from "@/lib/pki/ca";
import { issueCertificate } from "@/lib/pki/certificates";
import { CA_ALGORITHM } from "@/lib/pki/policy";
import { seedUsers } from "@/prisma/fixtures";
import { resetDatabase } from "@/tests/helpers/db";
import { ensureMasterKey } from "@/tests/helpers/master-key";

let signer: Actor;
let viewer: Actor;
let signedId: string;

beforeAll(async () => {
  ensureMasterKey();
  await resetDatabase();
  await seedUsers();
  await ensureRootCa();
  const users = await prisma.user.findMany();
  const actorFor = (email: string, role: Actor["role"]): Actor => ({ userId: users.find((user) => user.email === email)!.id, email, role });
  signer = actorFor("signer@demo", "SIGNER");
  viewer = actorFor("viewer@demo", "VIEWER");
  const verifier = actorFor("verifier@demo", "VERIFIER");

  const certificate = await issueCertificate({ actor: signer, algorithm: CA_ALGORITHM });
  const signed = await uploadDocument({ actor: signer, filename: "overview-signed.txt", mimeType: "text/plain", bytes: Buffer.from("signed for the overview") });
  await uploadDocument({ actor: signer, filename: "overview-unsigned.txt", mimeType: "text/plain", bytes: Buffer.from("never signed") });
  await signDocument({ actor: signer, documentId: signed.id, certificateId: certificate.id });
  await verifyDocument(verifier, signed.id);
  signedId = signed.id;
}, 60_000);

describe("system overview", () => {
  it("reports document, signature and certificate counts from the database", async () => {
    const overview = await systemOverview(viewer);

    expect(overview.documents.total).toBe(2);
    expect(overview.documents.byStatus.reduce((sum, row) => sum + row.count, 0)).toBe(2);
    expect(overview.signatures.total).toBe(1);
    expect(overview.signatures.timestamped).toBe(1);
    expect(overview.signatures.withCms).toBe(1);
    expect(overview.signatures.byAlgorithm).toEqual([{ key: orchestrator.displayName(CA_ALGORITHM), count: 1 }]);
    expect(overview.certificates.byStatus).toEqual([{ key: "ACTIVE", count: 1 }]);
  });

  it("lists the recent verification with its real verdict and document", async () => {
    const [latest] = (await systemOverview(viewer)).recentVerifications;
    expect(latest).toMatchObject({ documentId: signedId, filename: "overview-signed.txt", outcome: "VALID", reason: null });
  });

  it("reports trust services and integrity state as stored", async () => {
    const overview = await systemOverview(viewer);
    expect(overview.trustServices.ca?.algorithm).toBe(orchestrator.displayName(CA_ALGORITHM));
    expect(overview.trustServices.tsa).not.toBeNull();
    expect(overview.integrity.auditEntries).toBe(await prisma.auditLogEntry.count());
    expect(overview.integrity.latestCheckpoint).toBeNull();
    expect(overview.integrity.entriesAfterLatestCheckpoint).toBe(overview.integrity.auditEntries);
    expect(overview.recentActivity[0].seq).toBe((await prisma.auditLogEntry.findFirstOrThrow({ orderBy: { seq: "desc" } })).seq);
  });
});
