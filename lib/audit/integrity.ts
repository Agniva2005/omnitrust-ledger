// Audit & Monitoring layer: walk the chain and recompute it.
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

/**
 * Recomputes every entry hash from the entry's own fields and its predecessor's hash.
 * Editing any stored field, deleting an entry, or reordering the log all surface here.
 */
export async function verifyAuditChain(): Promise<IntegrityResult> {
  const entries = await prisma.auditLogEntry.findMany({ orderBy: { seq: "asc" } });
  const breaks: ChainBreak[] = [];

  let expectedSeq = 1;
  let expectedPrevHash = GENESIS_HASH;

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

    // The next entry is expected to link to what this one *recomputes* to, not to the
    // hash it happens to store. That is what makes a single edit break the chain from
    // that point onwards rather than being contained to one row.
    expectedPrevHash = recomputed;
    expectedSeq = entry.seq + 1;
  }

  return {
    valid: breaks.length === 0,
    entriesChecked: entries.length,
    firstBreak: breaks[0],
    breaks,
    checkedAt: new Date(),
  };
}
