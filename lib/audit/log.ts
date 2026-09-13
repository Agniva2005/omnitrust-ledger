// Audit & Monitoring layer: an append-only, hash-chained log.
//
//   entryHash = SHA256(prevHash + canonical serialisation of this entry's own fields)
//
// Every security-relevant action appends one entry. Nothing in the application ever
// updates or deletes an entry, so any change to a stored row breaks the chain from
// that point onwards and lib/audit/integrity.ts can say exactly where.
import type { AuditLogEntry } from "@prisma/client";
import { sha256Hex } from "@/lib/crypto/hash";
import { prisma } from "@/lib/db";

export const AUDIT_ACTIONS = [
  "USER_LOGIN",
  "USER_LOGIN_FAILED",
  "USER_LOGIN_THROTTLED",
  "USER_LOGOUT",
  "DOCUMENT_UPLOADED",
  "DOCUMENT_VERSION_ADDED",
  "DOCUMENT_SIGNED",
  "DOCUMENT_VERIFIED",
  "DOCUMENT_EXPORTED",
  "CERTIFICATE_ISSUED",
  "CERTIFICATE_REVOKED",
  "CRL_ISSUED",
  "TIMESTAMP_ISSUED",
  "TIMESTAMP_UNAVAILABLE",
  "KEY_LIFECYCLE_CHANGED",
] as const;

export type AuditAction = (typeof AUDIT_ACTIONS)[number];

/** The prevHash of the first entry: 32 zero bytes. */
export const GENESIS_HASH = "0".repeat(64);

export type AuditEntryFields = {
  seq: number;
  actorUserId: string | null;
  action: string;
  targetType: string;
  targetId: string;
  metadataJson: string;
  createdAt: Date;
};

/**
 * Canonical serialisation. Field order is fixed here rather than relying on object key
 * order, and the separator cannot appear unescaped in any field, so two different
 * entries can never serialise identically.
 */
export function canonicalEntry(entry: AuditEntryFields): string {
  return [
    entry.seq,
    entry.actorUserId ?? "",
    entry.action,
    entry.targetType,
    entry.targetId,
    entry.metadataJson,
    entry.createdAt.toISOString(),
  ]
    .map((field) => String(field).replace(/\\/g, "\\\\").replace(/\|/g, "\\|"))
    .join("|");
}

export function computeEntryHash(prevHash: string, entry: AuditEntryFields): string {
  return sha256Hex(prevHash + canonicalEntry(entry));
}

/** Metadata is stringified with sorted keys so the same data always hashes the same. */
export function serialiseMetadata(metadata: Record<string, unknown> = {}): string {
  const sorted: Record<string, unknown> = {};
  for (const key of Object.keys(metadata).sort()) sorted[key] = metadata[key];
  return JSON.stringify(sorted);
}

export type AppendInput = {
  actorUserId?: string | null;
  action: AuditAction;
  targetType: string;
  targetId: string;
  metadata?: Record<string, unknown>;
};

// Appends are serialised in-process: each waits for the previous one to finish, so two
// concurrent requests cannot read the same tail and compute the same seq. The unique
// constraint on `seq` is the backstop -- a losing writer retries against the new tail.
let appendQueue: Promise<unknown> = Promise.resolve();

const MAX_ATTEMPTS = 5;

export function appendAuditEntry(input: AppendInput): Promise<AuditLogEntry> {
  const result = appendQueue.then(
    () => appendOnce(input),
    () => appendOnce(input),
  );
  appendQueue = result.catch(() => undefined);
  return result;
}

async function appendOnce(input: AppendInput): Promise<AuditLogEntry> {
  let lastError: unknown;

  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt += 1) {
    const tail = await prisma.auditLogEntry.findFirst({ orderBy: { seq: "desc" } });
    const fields: AuditEntryFields = {
      seq: (tail?.seq ?? 0) + 1,
      actorUserId: input.actorUserId ?? null,
      action: input.action,
      targetType: input.targetType,
      targetId: input.targetId,
      metadataJson: serialiseMetadata(input.metadata),
      createdAt: new Date(),
    };
    const prevHash = tail?.entryHash ?? GENESIS_HASH;

    try {
      return await prisma.auditLogEntry.create({
        data: { ...fields, prevHash, entryHash: computeEntryHash(prevHash, fields) },
      });
    } catch (error) {
      // Unique violation on seq: another writer got there first, so re-read the tail.
      lastError = error;
    }
  }

  throw lastError;
}

export async function listAuditEntries(limit = 200) {
  return prisma.auditLogEntry.findMany({
    orderBy: { seq: "desc" },
    take: limit,
    include: { actor: { select: { email: true } } },
  });
}

export async function auditEntryCount(): Promise<number> {
  return prisma.auditLogEntry.count();
}
