// Demonstration-only tampering of the real audit log, for showing detection live.
//
// The log is append-only by design and nothing in the application ever edits an entry. This
// module is the deliberate exception, so that the integrity walk and the signed checkpoints can
// be shown catching a real edit to real rows rather than a scripted message or a sandbox copy.
//
// Every row that is about to change is snapshotted first, so Restore puts the log back exactly
// as it was — including an entry that was deleted outright. It sits behind the ADMIN-only
// demo:tamper capability, which a real deployment would drop along with this file.
import fs from "node:fs/promises";
import path from "node:path";
import { ConflictError, NotFoundError } from "@/lib/api";
import { GENESIS_HASH, appendAuditEntry, computeEntryHash, serialiseMetadata } from "@/lib/audit/log";
import { requireCapability, type Actor } from "@/lib/auth/rbac";
import { prisma } from "@/lib/db";
import { storageRoot } from "@/lib/documents/storage";

type Snapshot = {
  id: string;
  seq: number;
  actorUserId: string | null;
  action: string;
  targetType: string;
  targetId: string;
  metadataJson: string;
  prevHash: string;
  entryHash: string;
  createdAt: string;
};

export type AuditTamperState = {
  altered: boolean;
  snapshotRows: number;
};

function snapshotPath(): string {
  return path.join(storageRoot(), "demo-tamper", "audit-log.json");
}

async function readSnapshot(): Promise<Snapshot[] | null> {
  try {
    return JSON.parse(await fs.readFile(snapshotPath(), "utf8")) as Snapshot[];
  } catch {
    return null;
  }
}

/** Keeps the first snapshot only, so tampering twice cannot overwrite the good copy. */
async function keepSnapshot(rows: Snapshot[]): Promise<void> {
  if (await readSnapshot()) return;
  await fs.mkdir(path.dirname(snapshotPath()), { recursive: true });
  await fs.writeFile(snapshotPath(), JSON.stringify(rows, null, 2));
}

async function snapshotFrom(seq: number): Promise<void> {
  const rows = await prisma.auditLogEntry.findMany({ where: { seq: { gte: seq } }, orderBy: { seq: "asc" } });
  await keepSnapshot(rows.map((row) => ({ ...row, createdAt: row.createdAt.toISOString() })));
}

export async function auditTamperState(): Promise<AuditTamperState> {
  const snapshot = await readSnapshot();
  return { altered: snapshot !== null, snapshotRows: snapshot?.length ?? 0 };
}

async function entryAt(seq: number) {
  const entry = await prisma.auditLogEntry.findFirst({ where: { seq } });
  if (!entry) throw new NotFoundError(`No audit entry at sequence ${seq}`);
  return entry;
}

/**
 * Edits one entry's metadata and leaves every stored hash alone: the crudest attack, and the
 * one a plain hash chain is meant to catch at exactly that sequence number.
 */
export async function tamperAuditEntry(actor: Actor, seq: number, replacement: string): Promise<AuditTamperState> {
  requireCapability(actor, "demo:tamper");
  const entry = await entryAt(seq);
  await snapshotFrom(seq);

  await prisma.auditLogEntry.update({
    where: { id: entry.id },
    data: { metadataJson: serialiseMetadata({ tamperedTo: replacement }) },
  });

  await appendAuditEntry({
    actorUserId: actor.userId,
    action: "DEMO_AUDIT_TAMPERED",
    targetType: "AuditLogEntry",
    targetId: entry.id,
    metadata: { seq, style: "metadata edit", replacement },
  });
  return auditTamperState();
}

/** Deletes an entry outright, which shows up as a gap in the sequence rather than a bad hash. */
export async function deleteAuditEntry(actor: Actor, seq: number): Promise<AuditTamperState> {
  requireCapability(actor, "demo:tamper");
  const entry = await entryAt(seq);
  await snapshotFrom(seq);

  await prisma.auditLogEntry.delete({ where: { id: entry.id } });

  await appendAuditEntry({
    actorUserId: actor.userId,
    action: "DEMO_AUDIT_TAMPERED",
    targetType: "AuditLogEntry",
    targetId: entry.id,
    metadata: { seq, style: "entry deleted" },
  });
  return auditTamperState();
}

/**
 * The attack the chain alone cannot survive: edit an entry, then recompute and rewrite every
 * later hash so the chain is internally consistent again. Only a commitment made *before* the
 * rewrite — a signed, time-stamped checkpoint — still disagrees.
 */
export async function rewriteAuditChain(actor: Actor, seq: number, replacement: string): Promise<AuditTamperState> {
  requireCapability(actor, "demo:tamper");
  await entryAt(seq);
  await snapshotFrom(1);

  const entries = await prisma.auditLogEntry.findMany({ orderBy: { seq: "asc" } });
  let prevHash = GENESIS_HASH;
  for (const entry of entries) {
    const metadataJson = entry.seq === seq ? serialiseMetadata({ tamperedTo: replacement }) : entry.metadataJson;
    const entryHash = computeEntryHash(prevHash, { ...entry, metadataJson });
    await prisma.auditLogEntry.update({ where: { id: entry.id }, data: { metadataJson, prevHash, entryHash } });
    prevHash = entryHash;
  }

  await appendAuditEntry({
    actorUserId: actor.userId,
    action: "DEMO_AUDIT_TAMPERED",
    targetType: "AuditLogEntry",
    targetId: String(seq),
    metadata: { seq, style: "consistent rewrite", entriesRewritten: entries.length, replacement },
  });
  return auditTamperState();
}

/** Puts every snapshotted row back, re-creating any that were deleted. */
export async function restoreAuditLog(actor: Actor): Promise<AuditTamperState> {
  requireCapability(actor, "demo:tamper");
  const snapshot = await readSnapshot();
  if (!snapshot) throw new ConflictError("Nothing to restore: the audit log has not been altered");

  for (const row of snapshot) {
    const data = {
      seq: row.seq,
      actorUserId: row.actorUserId,
      action: row.action,
      targetType: row.targetType,
      targetId: row.targetId,
      metadataJson: row.metadataJson,
      prevHash: row.prevHash,
      entryHash: row.entryHash,
      createdAt: new Date(row.createdAt),
    };
    await prisma.auditLogEntry.upsert({ where: { id: row.id }, update: data, create: { id: row.id, ...data } });
  }

  // Entries appended after the snapshot chain onto a tail that has just moved back, so they are
  // removed too rather than left pointing at a hash that no longer exists.
  const highest = Math.max(...snapshot.map((row) => row.seq));
  await prisma.auditLogEntry.deleteMany({ where: { seq: { gt: highest } } });

  await fs.rm(snapshotPath(), { force: true });

  // Appended after the truncation so the restore is itself on the record.
  await appendAuditEntry({
    actorUserId: actor.userId,
    action: "DEMO_AUDIT_RESTORED",
    targetType: "AuditLogEntry",
    targetId: String(highest),
    metadata: { rowsRestored: snapshot.length, throughSeq: highest },
  });
  return auditTamperState();
}
