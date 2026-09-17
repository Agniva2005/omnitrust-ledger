import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import {
  auditTamperState,
  deleteAuditEntry,
  restoreAuditLog,
  rewriteAuditChain,
  tamperAuditEntry,
} from "@/lib/audit/demo-tamper";
import { verifyAuditChain } from "@/lib/audit/integrity";
import { appendAuditEntry } from "@/lib/audit/log";
import { AuthorizationError, type Actor } from "@/lib/auth/rbac";
import { prisma } from "@/lib/db";
import { createAuditCheckpoint, verifyAuditLog } from "@/lib/pki/audit-checkpoints";
import { ensureRootCa } from "@/lib/pki/ca";
import { seedUsers } from "@/prisma/fixtures";
import { resetDatabase } from "@/tests/helpers/db";
import { ensureMasterKey } from "@/tests/helpers/master-key";

let admin: Actor;
let signer: Actor;

beforeAll(() => {
  ensureMasterKey();
});

/** A short log of real entries to attack. */
async function freshLog(entries = 6) {
  await resetDatabase();
  await seedUsers();
  const users = await prisma.user.findMany();
  admin = { userId: users.find((user) => user.email === "admin@demo")!.id, email: "admin@demo", role: "ADMIN" };
  signer = { userId: users.find((user) => user.email === "signer@demo")!.id, email: "signer@demo", role: "SIGNER" };

  for (let index = 0; index < entries; index += 1) {
    await appendAuditEntry({
      actorUserId: admin.userId,
      action: "USER_LOGIN",
      targetType: "User",
      targetId: admin.userId,
      metadata: { attempt: index },
    });
  }
}

beforeEach(async () => {
  await freshLog();
});

describe("demonstration tampering of the audit log", () => {
  it("an edited entry breaks the chain at exactly that sequence, and restore repairs it", async () => {
    expect((await verifyAuditChain()).valid).toBe(true);

    await tamperAuditEntry(admin, 3, "edited by an attacker");

    const broken = await verifyAuditChain();
    expect(broken.valid).toBe(false);
    expect(broken.firstBreak?.seq).toBe(3);
    expect(broken.firstBreak?.problem).toBe("ENTRY_HASH_MISMATCH");

    await restoreAuditLog(admin);
    expect((await verifyAuditChain()).valid).toBe(true);
    expect((await auditTamperState()).altered).toBe(false);
  });

  it("a deleted entry shows as a gap, and restore puts the row back", async () => {
    const before = await prisma.auditLogEntry.findFirstOrThrow({ where: { seq: 3 } });

    await deleteAuditEntry(admin, 3);
    expect(await prisma.auditLogEntry.findFirst({ where: { seq: 3 } })).toBeNull();
    expect((await verifyAuditChain()).firstBreak?.problem).toBe("SEQUENCE_GAP");

    await restoreAuditLog(admin);
    const after = await prisma.auditLogEntry.findFirstOrThrow({ where: { seq: 3 } });
    // The same row, not a lookalike: id, hashes and timestamp all come back.
    expect(after.id).toBe(before.id);
    expect(after.entryHash).toBe(before.entryHash);
    expect(after.prevHash).toBe(before.prevHash);
    expect(after.createdAt.toISOString()).toBe(before.createdAt.toISOString());
    expect((await verifyAuditChain()).valid).toBe(true);
  });

  it("a consistent rewrite satisfies the chain but not a checkpoint made beforehand", async () => {
    await ensureRootCa();
    await createAuditCheckpoint(admin);

    await rewriteAuditChain(admin, 2, "edited by an attacker");

    // The attacker recomputed every later hash, so the chain alone is fooled.
    expect((await verifyAuditChain()).valid).toBe(true);

    const verified = await verifyAuditLog();
    expect(verified.valid).toBe(false);
    expect(verified.checkpoints.some((checkpoint) => checkpoint.valid === false)).toBe(true);

    await restoreAuditLog(admin);
    const repaired = await verifyAuditLog();
    expect(repaired.chain.valid).toBe(true);
    expect(repaired.checkpoints.every((checkpoint) => checkpoint.valid)).toBe(true);
  }, 60_000);

  it("refuses every action to a role without the capability", async () => {
    await expect(tamperAuditEntry(signer, 2, "x")).rejects.toThrow(AuthorizationError);
    await expect(deleteAuditEntry(signer, 2)).rejects.toThrow(AuthorizationError);
    await expect(rewriteAuditChain(signer, 2, "x")).rejects.toThrow(AuthorizationError);
    await expect(restoreAuditLog(signer)).rejects.toThrow(AuthorizationError);
  });

  it("refuses to restore a log that was never altered, and to attack an entry that is not there", async () => {
    await expect(restoreAuditLog(admin)).rejects.toThrow(/has not been altered/);
    await expect(tamperAuditEntry(admin, 9999, "x")).rejects.toThrow(/No audit entry at sequence/);
  });
});
