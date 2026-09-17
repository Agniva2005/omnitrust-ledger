// The audit log as a takeaway archive.
//
// Reading the log on screen proves nothing to someone who was not there. This writes out every
// entry with the hashes it stores, the checkpoints that commit to the chain, the result of the
// integrity walk, and — the part that matters — the exact rule for recomputing the chain, so a
// recipient can check it with their own code instead of trusting this application's verdict.
import { appendAuditEntry, canonicalEntry } from "@/lib/audit/log";
import { walkAuditChain } from "@/lib/audit/integrity";
import { requireCapability, type Actor } from "@/lib/auth/rbac";
import { sha256Hex } from "@/lib/crypto/hash";
import { prisma } from "@/lib/db";
import { createZip, type ZipEntry } from "@/lib/evidence/zip";
import { verifyAuditLog } from "@/lib/pki/audit-checkpoints";

function readme(entries: number, valid: boolean, checkpoints: number): string {
  return `OmniTrust Ledger — audit log export
===================================

Entries      ${entries}
Chain        ${valid ? "verifies" : "DOES NOT VERIFY — see integrity.json"}
Checkpoints  ${checkpoints}

Contents
--------
  entries.json      every entry, with the prevHash and entryHash it stores
  checkpoints.json  the signed, time-stamped commitments to the chain head
  integrity.json    this installation's own walk of the chain, and any breaks
  README.txt        this description

Recomputing the chain yourself
------------------------------
Each entry's hash is

    entryHash = SHA256( prevHash || canonical(entry) )

where prevHash is the previous entry's entryHash, the first entry uses 64 zero
characters, and canonical(entry) joins these fields in this order with "|":

    seq, actorUserId (empty string when null), action, targetType, targetId,
    metadataJson, createdAt as an ISO-8601 string

Before joining, every field has backslashes escaped as "\\\\" and pipes as "\\|",
so no field can forge a separator. All hashes are lowercase hex of SHA-256.

Walk the entries in seq order, recompute each hash, and compare. An entry whose
recomputed hash differs from its stored one was altered. An entry whose prevHash
is not the previous entry's stored hash means the chain was cut or reordered.

A chain that recomputes cleanly is not on its own proof of an untouched log:
whoever holds the database can edit an entry and recompute every later hash.
That is what the checkpoints are for — each signs a chain head at a point in
time, so a rewrite of anything before it no longer matches.
`;
}

export type AuditPack = { filename: string; bytes: Buffer; entries: number; valid: boolean };

export async function buildAuditPack(actor: Actor): Promise<AuditPack> {
  requireCapability(actor, "audit:read");
  requireCapability(actor, "audit:verify");

  const rows = await prisma.auditLogEntry.findMany({
    orderBy: { seq: "asc" },
    include: { actor: { select: { email: true } } },
  });
  const walk = await walkAuditChain();
  const verified = await verifyAuditLog();

  const entries = rows.map((row) => ({
    seq: row.seq,
    createdAt: row.createdAt.toISOString(),
    actorUserId: row.actorUserId,
    actorEmail: row.actor?.email ?? null,
    action: row.action,
    targetType: row.targetType,
    targetId: row.targetId,
    metadataJson: row.metadataJson,
    prevHash: row.prevHash,
    entryHash: row.entryHash,
    // The exact string that was hashed, so a reader never has to guess the serialisation.
    canonical: canonicalEntry(row),
  }));

  const checkpoints = verified.checkpoints.map((checkpoint) => ({ ...checkpoint }));

  const files: ZipEntry[] = [
    { name: "entries.json", data: Buffer.from(JSON.stringify(entries, null, 2), "utf8") },
    { name: "checkpoints.json", data: Buffer.from(JSON.stringify(checkpoints, null, 2), "utf8") },
    {
      name: "integrity.json",
      data: Buffer.from(JSON.stringify({ chain: walk.result, overallValid: verified.valid, head: verified.head }, null, 2), "utf8"),
    },
    { name: "README.txt", data: Buffer.from(readme(entries.length, walk.result.valid, checkpoints.length), "utf8") },
  ];

  const builtAt = new Date();
  const bytes = createZip(files, builtAt);

  await appendAuditEntry({
    actorUserId: actor.userId,
    action: "AUDIT_EXPORTED",
    targetType: "AuditLog",
    targetId: String(walk.lastSeq ?? 0),
    metadata: { entries: entries.length, chainValid: walk.result.valid, packSha256: sha256Hex(bytes) },
  });

  return {
    filename: `omnitrust-audit-log-${builtAt.toISOString().slice(0, 10)}.zip`,
    bytes,
    entries: entries.length,
    valid: walk.result.valid,
  };
}
