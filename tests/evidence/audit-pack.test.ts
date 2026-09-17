// The audit log export. Its whole purpose is that someone who was not here can recheck the
// chain with their own code, so the test rebuilds the chain from the archive's contents using
// only the rule the README states, rather than calling the application's own integrity walk.
import zlib from "node:zlib";
import { createHash } from "node:crypto";
import { beforeAll, describe, expect, it } from "vitest";
import { appendAuditEntry } from "@/lib/audit/log";
import { AuthorizationError, type Actor } from "@/lib/auth/rbac";
import { prisma } from "@/lib/db";
import { buildAuditPack } from "@/lib/evidence/audit-pack";
import { seedUsers } from "@/prisma/fixtures";
import { resetDatabase } from "@/tests/helpers/db";
import { ensureMasterKey } from "@/tests/helpers/master-key";

const GENESIS = "0".repeat(64);

type Exported = {
  seq: number;
  createdAt: string;
  actorUserId: string | null;
  action: string;
  targetType: string;
  targetId: string;
  metadataJson: string;
  prevHash: string;
  entryHash: string;
  canonical: string;
};

/** The README's rule, written out again here rather than imported from the application. */
function canonicalFromReadme(entry: Exported): string {
  return [entry.seq, entry.actorUserId ?? "", entry.action, entry.targetType, entry.targetId, entry.metadataJson, entry.createdAt]
    .map((field) => String(field).replace(/\\/g, "\\\\").replace(/\|/g, "\\|"))
    .join("|");
}

/** Reads a stored entry out of the archive by name, via its central directory. */
function readArchiveFile(archive: Buffer, name: string): Buffer {
  const endOffset = archive.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  const count = archive.readUInt16LE(endOffset + 10);
  let cursor = archive.readUInt32LE(endOffset + 16);

  for (let index = 0; index < count; index += 1) {
    const size = archive.readUInt32LE(cursor + 24);
    const nameLength = archive.readUInt16LE(cursor + 28);
    const localOffset = archive.readUInt32LE(cursor + 42);
    const entryName = archive.subarray(cursor + 46, cursor + 46 + nameLength).toString("utf8");
    const storedCrc = archive.readUInt32LE(cursor + 16);

    if (entryName === name) {
      const localNameLength = archive.readUInt16LE(localOffset + 26);
      const extraLength = archive.readUInt16LE(localOffset + 28);
      const start = localOffset + 30 + localNameLength + extraLength;
      const data = archive.subarray(start, start + size);
      expect(zlib.crc32(data), `${name} checksum`).toBe(storedCrc);
      return data;
    }
    cursor += 46 + nameLength + archive.readUInt16LE(cursor + 30) + archive.readUInt16LE(cursor + 32);
  }
  throw new Error(`${name} is not in the archive`);
}

let admin: Actor;
let viewer: Actor;

beforeAll(async () => {
  ensureMasterKey();
  await resetDatabase();
  await seedUsers();

  const users = await prisma.user.findMany();
  const id = (email: string) => users.find((user) => user.email === email)!.id;
  admin = { userId: id("admin@demo"), email: "admin@demo", role: "ADMIN" };
  viewer = { userId: id("viewer@demo"), email: "viewer@demo", role: "VIEWER" };

  for (let index = 0; index < 5; index += 1) {
    await appendAuditEntry({
      actorUserId: admin.userId,
      // Metadata containing the separator and an escape, so the canonical form is exercised.
      action: "USER_LOGIN",
      targetType: "User",
      targetId: admin.userId,
      metadata: { note: `pipe | and backslash \\ number ${index}` },
    });
  }
}, 60_000);

describe("the audit log export", () => {
  it("lets the chain be rebuilt from the archive alone, using only the documented rule", async () => {
    const pack = await buildAuditPack(admin);
    const entries = JSON.parse(readArchiveFile(pack.bytes, "entries.json").toString("utf8")) as Exported[];
    expect(entries.length).toBeGreaterThanOrEqual(5);

    let previous = GENESIS;
    for (const entry of entries) {
      // The canonical string shipped in the archive must match the documented rule exactly,
      // or a reader following the README would compute different hashes than this app did.
      expect(canonicalFromReadme(entry), `canonical at seq ${entry.seq}`).toBe(entry.canonical);
      expect(entry.prevHash, `link at seq ${entry.seq}`).toBe(previous);

      const recomputed = createHash("sha256").update(previous + canonicalFromReadme(entry)).digest("hex");
      expect(recomputed, `hash at seq ${entry.seq}`).toBe(entry.entryHash);
      previous = entry.entryHash;
    }
  }, 60_000);

  it("carries the integrity result, the checkpoints and a README", async () => {
    const pack = await buildAuditPack(admin);
    const integrity = JSON.parse(readArchiveFile(pack.bytes, "integrity.json").toString("utf8"));
    expect(integrity.chain.valid).toBe(true);
    expect(JSON.parse(readArchiveFile(pack.bytes, "checkpoints.json").toString("utf8"))).toBeInstanceOf(Array);

    const readme = readArchiveFile(pack.bytes, "README.txt").toString("utf8");
    expect(readme).toContain("SHA256( prevHash || canonical(entry) )");
    // The README must warn that a clean chain alone is not proof, or it overstates the evidence.
    expect(readme).toMatch(/recompute every later hash/);
    expect(pack.valid).toBe(true);
  }, 60_000);

  it("records its own export in the log, and refuses a role that cannot verify", async () => {
    const before = await prisma.auditLogEntry.count();
    await buildAuditPack(admin);
    expect(await prisma.auditLogEntry.count()).toBe(before + 1);
    expect(await prisma.auditLogEntry.findFirst({ where: { action: "AUDIT_EXPORTED" }, orderBy: { seq: "desc" } })).not.toBeNull();

    await expect(buildAuditPack(viewer)).rejects.toThrow(AuthorizationError);
  }, 60_000);
});
