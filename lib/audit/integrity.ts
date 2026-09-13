// Audit & Monitoring layer: walk the chain and recompute it.
import type { AuditLogEntry } from "@prisma/client";
import { prisma } from "@/lib/db";
import { GENESIS_HASH, computeEntryHash } from "@/lib/audit/log";

export type ChainBreak = {
  seq: number;
  entryId: string;
  problem: "SEQUENCE_GAP" | "PREV_HASH_MISMATCH" | "ENTRY_HASH_MISMATCH";
  detail: string;
};

export type IntegrityResult = {
  valid: boolean;
  entriesChecked: number;
  /** The first entry at which the chain stops verifying, if any. */
  firstBreak?: ChainBreak;
  breaks: ChainBreak[];
  checkedAt: Date;
};

export type ChainWalk = {
  result: IntegrityResult;
  /** The highest sequence number present, or null for an empty log. */
  lastSeq: number | null;
  /**
   * Each entry's hash derived from the genesis hash through its predecessors' fields, ignoring
   * every stored hash. This is what a signed checkpoint commits to, so it changes whenever any
   * earlier entry changes, even if an attacker recomputed and rewrote all stored hashes.
   */
  derivedHashBySeq: Map<number, string>;
};

/**
 * Recomputes every entry hash from the entry's own fields and its predecessor's hash.
 * Editing any stored field, deleting an entry, or reordering the log all surface here, unless
 * every later hash was recomputed and rewritten too, or entries were deleted from the end.
 * Those two cases need an external commitment: see lib/pki/audit-checkpoints.ts.
 */
export async function walkAuditChain(): Promise<ChainWalk> {
  const entries: AuditLogEntry[] = await prisma.auditLogEntry.findMany({ orderBy: { seq: "asc" } });
  const breaks: ChainBreak[] = [];
  const derivedHashBySeq = new Map<number, string>();

  let expectedSeq = 1;
  let expectedPrevHash = GENESIS_HASH;
  let derivedPrevHash = GENESIS_HASH;

  for (const entry of entries) {
    if (entry.seq !== expectedSeq) {
      breaks.push({
        seq: entry.seq,
        entryId: entry.id,
        problem: "SEQUENCE_GAP",
        detail: `expected sequence ${expectedSeq}, found ${entry.seq}: an entry is missing or reordered`,
      });
      expectedSeq = entry.seq;
    }

    if (entry.prevHash !== expectedPrevHash) {
      breaks.push({
        seq: entry.seq,
        entryId: entry.id,
        problem: "PREV_HASH_MISMATCH",
        detail: `entry ${entry.seq} links to ${entry.prevHash.slice(0, 16)}... but the previous entry hashes to ${expectedPrevHash.slice(0, 16)}...`,
      });
    }

    const recomputed = computeEntryHash(entry.prevHash, entry);
    if (recomputed !== entry.entryHash) {
      breaks.push({
        seq: entry.seq,
        entryId: entry.id,
        problem: "ENTRY_HASH_MISMATCH",
        detail: `entry ${entry.seq} (${entry.action}) stores ${entry.entryHash.slice(0, 16)}... but its contents hash to ${recomputed.slice(0, 16)}...: this entry was altered`,
      });
    }

    derivedPrevHash = computeEntryHash(derivedPrevHash, entry);
    derivedHashBySeq.set(entry.seq, derivedPrevHash);

    // The next entry is expected to link to what this one *recomputes* to, not to the
    // hash it happens to store. That is what makes a single edit break the chain from
    // that point onwards rather than being contained to one row.
    expectedPrevHash = recomputed;
    expectedSeq = entry.seq + 1;
  }

  return {
    result: {
      valid: breaks.length === 0,
      entriesChecked: entries.length,
      firstBreak: breaks[0],
      breaks,
      checkedAt: new Date(),
    },
    lastSeq: entries.length > 0 ? entries[entries.length - 1].seq : null,
    derivedHashBySeq,
  };
}

export async function verifyAuditChain(): Promise<IntegrityResult> {
  return (await walkAuditChain()).result;
}
