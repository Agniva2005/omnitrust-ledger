// Consent-based sharing: a holder lets someone without an account verify one document version.
//
// This is the first surface in the application that serves a document to an unauthenticated
// caller, so the rules are deliberately narrow. A share names one version of one document and
// nothing else. It always expires. It can be withdrawn at any moment, and revocation is checked
// on every access rather than at creation. Creating, opening and withdrawing a share each append
// to the hash-chained audit log, so the holder keeps a trail of who they gave access to that
// even the operator of this installation cannot quietly rewrite.
//
// Only a SHA-256 of the token is stored. A copy of the database therefore grants access to
// nothing: the link exists only where the holder put it.
import { randomBytes } from "node:crypto";
import { ConflictError, NotFoundError } from "@/lib/api";
import { appendAuditEntry } from "@/lib/audit/log";
import { requireCapability, type Actor } from "@/lib/auth/rbac";
import { sha256Hex } from "@/lib/crypto/hash";
import { prisma } from "@/lib/db";

const TOKEN_BYTES = 32;
const DEFAULT_DAYS = 7;
const MAX_DAYS = 90;
const MAX_AUDIENCE = 120;
const MAX_NOTE = 500;

export type ShareSummary = {
  id: string;
  versionNumber: number;
  audience: string;
  note: string | null;
  createdBy: string;
  createdAt: string;
  expiresAt: string;
  revokedAt: string | null;
  accessCount: number;
  lastAccessedAt: string | null;
  /** Derived for the interface, so one word describes a share rather than three fields. */
  state: "ACTIVE" | "EXPIRED" | "WITHDRAWN";
};

function stateOf(share: { expiresAt: Date; revokedAt: Date | null }, at: Date): ShareSummary["state"] {
  if (share.revokedAt) return "WITHDRAWN";
  return share.expiresAt <= at ? "EXPIRED" : "ACTIVE";
}

function summarise(share: {
  id: string;
  versionNumber: number;
  audience: string;
  note: string | null;
  createdAt: Date;
  expiresAt: Date;
  revokedAt: Date | null;
  accessCount: number;
  lastAccessedAt: Date | null;
  createdBy: { email: string };
}): ShareSummary {
  return {
    id: share.id,
    versionNumber: share.versionNumber,
    audience: share.audience,
    note: share.note,
    createdBy: share.createdBy.email,
    createdAt: share.createdAt.toISOString(),
    expiresAt: share.expiresAt.toISOString(),
    revokedAt: share.revokedAt?.toISOString() ?? null,
    accessCount: share.accessCount,
    lastAccessedAt: share.lastAccessedAt?.toISOString() ?? null,
    state: stateOf(share, new Date()),
  };
}

export type CreatedShare = { share: ShareSummary; token: string };

/**
 * Mints a share for a signed version. The token is returned exactly once: it is not stored and
 * cannot be shown again, which is what makes a leaked database useless on its own.
 */
export async function createShare(
  actor: Actor,
  documentId: string,
  input: { versionNumber?: number; audience: string; note?: string; days?: number },
): Promise<CreatedShare> {
  requireCapability(actor, "document:share");

  const document = await prisma.document.findUnique({
    where: { id: documentId },
    include: { versions: { orderBy: { versionNumber: "desc" }, include: { signatures: true } } },
  });
  if (!document) throw new NotFoundError("Document not found");
  if (document.ownerUserId !== actor.userId) {
    throw new ConflictError("Only the document's owner can share it");
  }

  const version =
    input.versionNumber === undefined
      ? document.versions[0]
      : document.versions.find((candidate) => candidate.versionNumber === input.versionNumber);
  if (!version) throw new NotFoundError("Document version not found");
  // Sharing an unsigned version would invite a verifier to check something with no signature.
  if (version.signatures.length === 0) {
    throw new ConflictError("That version is not signed, so there would be nothing for the recipient to verify");
  }

  const audience = input.audience.trim();
  if (audience.length === 0) throw new ConflictError("Say who this is being shared with");
  if (audience.length > MAX_AUDIENCE) throw new ConflictError(`The audience must be ${MAX_AUDIENCE} characters or fewer`);
  if ((input.note ?? "").length > MAX_NOTE) throw new ConflictError(`The note must be ${MAX_NOTE} characters or fewer`);

  const days = input.days ?? DEFAULT_DAYS;
  if (!Number.isInteger(days) || days < 1 || days > MAX_DAYS) {
    throw new ConflictError(`A share must last between 1 and ${MAX_DAYS} days`);
  }

  const token = randomBytes(TOKEN_BYTES).toString("base64url");
  const created = await prisma.documentShare.create({
    data: {
      documentId,
      versionNumber: version.versionNumber,
      tokenHash: sha256Hex(Buffer.from(token, "utf8")),
      audience,
      note: input.note?.trim() || null,
      createdByUserId: actor.userId,
      expiresAt: new Date(Date.now() + days * 24 * 60 * 60 * 1000),
    },
    include: { createdBy: { select: { email: true } } },
  });

  await appendAuditEntry({
    actorUserId: actor.userId,
    action: "DOCUMENT_SHARED",
    targetType: "Document",
    targetId: documentId,
    // The token is never recorded, here or anywhere.
    metadata: { shareId: created.id, versionNumber: version.versionNumber, audience, expiresAt: created.expiresAt.toISOString(), days },
  });

  return { share: summarise(created), token };
}

export async function listShares(actor: Actor, documentId: string): Promise<ShareSummary[]> {
  requireCapability(actor, "document:read");
  const shares = await prisma.documentShare.findMany({
    where: { documentId },
    orderBy: { createdAt: "desc" },
    include: { createdBy: { select: { email: true } } },
  });
  return shares.map(summarise);
}

export async function revokeShare(actor: Actor, shareId: string): Promise<ShareSummary> {
  requireCapability(actor, "document:share");

  const share = await prisma.documentShare.findUnique({
    where: { id: shareId },
    include: { createdBy: { select: { email: true } }, document: { select: { ownerUserId: true } } },
  });
  if (!share) throw new NotFoundError("Share not found");
  if (share.document.ownerUserId !== actor.userId) throw new ConflictError("Only the document's owner can withdraw a share");
  if (share.revokedAt) throw new ConflictError("That share has already been withdrawn");

  const updated = await prisma.documentShare.update({
    where: { id: shareId },
    data: { revokedAt: new Date() },
    include: { createdBy: { select: { email: true } } },
  });

  await appendAuditEntry({
    actorUserId: actor.userId,
    action: "DOCUMENT_SHARE_REVOKED",
    targetType: "Document",
    targetId: share.documentId,
    metadata: { shareId, audience: share.audience, accessCount: share.accessCount },
  });

  return summarise(updated);
}

export type ResolvedShare = {
  documentId: string;
  versionNumber: number;
  filename: string;
  audience: string;
  note: string | null;
  sharedBy: string;
  sharedAt: string;
  expiresAt: string;
  accessCount: number;
};

export class ShareUnavailableError extends Error {
  readonly reason: "NOT_FOUND" | "EXPIRED" | "WITHDRAWN";
  constructor(reason: ShareUnavailableError["reason"], message: string) {
    super(message);
    this.name = "ShareUnavailableError";
    this.reason = reason;
  }
}

/**
 * Resolves a token for an unauthenticated visitor, recording the access. Expiry and withdrawal
 * are judged here, on every open, rather than trusted from when the link was made.
 */
export async function openShare(token: string): Promise<ResolvedShare> {
  const share = await prisma.documentShare.findUnique({
    where: { tokenHash: sha256Hex(Buffer.from(token, "utf8")) },
    include: { document: { select: { filename: true } }, createdBy: { select: { email: true } } },
  });
  // An unknown token and a withdrawn one are told apart for the holder's trail, not for the
  // visitor: both simply cannot be opened.
  if (!share) throw new ShareUnavailableError("NOT_FOUND", "This link is not valid.");
  if (share.revokedAt) throw new ShareUnavailableError("WITHDRAWN", "This link has been withdrawn by the person who shared it.");
  if (share.expiresAt <= new Date()) throw new ShareUnavailableError("EXPIRED", "This link has expired.");

  const updated = await prisma.documentShare.update({
    where: { id: share.id },
    data: { accessCount: { increment: 1 }, lastAccessedAt: new Date() },
  });

  await appendAuditEntry({
    // No actor: whoever opened it has no account here, and the log should not imply one.
    actorUserId: null,
    action: "DOCUMENT_SHARE_ACCESSED",
    targetType: "Document",
    targetId: share.documentId,
    metadata: { shareId: share.id, audience: share.audience, accessCount: updated.accessCount },
  });

  return {
    documentId: share.documentId,
    versionNumber: share.versionNumber,
    filename: share.document.filename,
    audience: share.audience,
    note: share.note,
    sharedBy: share.createdBy.email,
    sharedAt: share.createdAt.toISOString(),
    expiresAt: share.expiresAt.toISOString(),
    accessCount: updated.accessCount,
  };
}
