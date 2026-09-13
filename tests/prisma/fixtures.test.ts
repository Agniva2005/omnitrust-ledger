// The seed is what a fresh clone and every demo start from, so its promises are tested
// rather than trusted: one signed sample per registered algorithm that verifies, a
// tampered sample that does not, an unsigned sample that is neither, an expired
// certificate, an intact audit chain, and idempotent re-seeding -- including on a
// database created by an earlier version of these fixtures.
import { beforeAll, describe, expect, it } from "vitest";
import { verifyAuditChain } from "@/lib/audit/integrity";
import type { Actor } from "@/lib/auth/rbac";
import { ALGORITHMS } from "@/lib/crypto/orchestrator";
import { prisma } from "@/lib/db";
import { uploadDocument } from "@/lib/documents/service";
import { DocumentNotSignedError, verifyDocument } from "@/lib/documents/verification";
import { seedAll, seedUsers, signedSampleFor } from "@/prisma/fixtures";
import { resetDatabase } from "@/tests/helpers/db";
import { ensureMasterKey } from "@/tests/helpers/master-key";

let seeded: Awaited<ReturnType<typeof seedAll>>;
let verifier: Actor;

async function counts() {
  return {
    documents: await prisma.document.count(),
    certificates: await prisma.certificate.count(),
    signatures: await prisma.signature.count(),
    users: await prisma.user.count(),
  };
}

beforeAll(async () => {
  ensureMasterKey();
  await resetDatabase();
  seeded = await seedAll();

  const user = await prisma.user.findUniqueOrThrow({ where: { email: "verifier@demo" } });
  verifier = { userId: user.id, email: user.email, role: "VERIFIER" };
}, 180_000);

describe("seeded data", () => {
  it("includes one signed sample per registered algorithm, each verifying VALID under that algorithm", async () => {
    expect(Object.keys(seeded.documents.signed).sort()).toEqual([...ALGORITHMS].sort());

    for (const algorithm of ALGORITHMS) {
      const { id } = seeded.documents.signed[algorithm];
      const signature = await prisma.signature.findFirstOrThrow({
        where: { documentVersion: { documentId: id } },
      });
      expect(signature.algorithm).toBe(algorithm);
      expect((await verifyDocument(verifier, id)).outcome).toBe("VALID");
    }
  });

  it("includes a pre-tampered document that verifies INVALID with HASH_MISMATCH", async () => {
    const result = await verifyDocument(verifier, seeded.documents.tampered.id);
    expect(result.outcome).toBe("INVALID");
    expect(result.reason).toBe("HASH_MISMATCH");
  });

  it("includes an unsigned document that is reported as not signed, not as invalid", async () => {
    await expect(verifyDocument(verifier, seeded.documents.unsigned.id)).rejects.toThrow(
      DocumentNotSignedError,
    );
  });

  it("includes an already-expired certificate for the expiry demonstration", async () => {
    expect(await prisma.certificate.count({ where: { expiresAt: { lt: new Date() } } })).toBeGreaterThan(0);
  });

  it("leaves the audit chain it created intact", async () => {
    expect((await verifyAuditChain()).valid).toBe(true);
  });
});

describe("re-seeding", () => {
  it("is idempotent: running it again creates nothing new", async () => {
    const before = await counts();
    await seedAll();
    expect(await counts()).toEqual(before);
  }, 120_000);

  it("reuses a sample stored under a different filename by an earlier version of the fixtures", async () => {
    await resetDatabase();
    await seedUsers();
    const signer = await prisma.user.findUniqueOrThrow({ where: { email: "signer@demo" } });
    const legacy = signedSampleFor(ALGORITHMS[0], 0);
    await uploadDocument({
      actor: { userId: signer.id, email: signer.email, role: "SIGNER" },
      filename: "legacy-sample-name.txt",
      mimeType: "text/plain",
      bytes: Buffer.from(legacy.contents),
    });

    const reseeded = await seedAll();

    expect(reseeded.documents.signed[ALGORITHMS[0]].filename).toBe("legacy-sample-name.txt");
    expect(await prisma.document.count({ where: { filename: legacy.filename } })).toBe(0);
  }, 180_000);
});
