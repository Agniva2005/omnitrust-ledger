// Document Management layer: upload, hashing, versioning, lifecycle bookkeeping.
import type { Document, DocumentVersion } from "@prisma/client";
import { BadRequestError, ConflictError, NotFoundError } from "@/lib/api";
import { requireCapability, type Actor } from "@/lib/auth/rbac";
import { sha256Hex } from "@/lib/crypto/hash";
import {
  assertDocumentState,
  assertPath,
  assertTransition,
  type DocumentState,
} from "@/lib/documents/lifecycle";
import { readBlob, versionStoragePath, writeBlob } from "@/lib/documents/storage";
import { prisma } from "@/lib/db";

export const MAX_UPLOAD_BYTES = 10 * 1024 * 1024;

export type UploadInput = {
  actor: Actor;
  filename: string;
  mimeType: string;
  bytes: Uint8Array;
};

function validateUpload({ filename, bytes }: Pick<UploadInput, "filename" | "bytes">) {
  if (bytes.byteLength === 0) {
    throw new BadRequestError("Refusing to store a zero-byte file: there is nothing to hash or sign");
  }
  if (bytes.byteLength > MAX_UPLOAD_BYTES) {
    throw new BadRequestError(
      `File is ${bytes.byteLength} bytes, over the ${MAX_UPLOAD_BYTES}-byte demo limit`,
    );
  }
  if (!filename.trim()) throw new BadRequestError("A filename is required");
}

/**
 * Creates a document at version 1. Runs the lifecycle path
 * CREATED -> UPLOADED -> HASHED, so the stored status reflects a real walk of the
 * Figure 4 state machine rather than a hard-coded string.
 */
export async function uploadDocument(input: UploadInput): Promise<Document> {
  requireCapability(input.actor, "document:upload");
  validateUpload(input);

  const hash = sha256Hex(input.bytes);

  const duplicate = await prisma.document.findFirst({
    where: { ownerUserId: input.actor.userId, currentHash: hash },
  });
  if (duplicate) {
    throw new ConflictError(
      `You have already uploaded these exact bytes as "${duplicate.filename}" (${duplicate.id}). ` +
        `Upload it as a new version of that document if you meant to supersede it.`,
    );
  }

  const status = assertPath(["CREATED", "UPLOADED", "HASHED"]);

  const document = await prisma.document.create({
    data: {
      ownerUserId: input.actor.userId,
      filename: input.filename.trim(),
      mimeType: input.mimeType || "application/octet-stream",
      storagePath: "",
      currentHash: hash,
      status,
    },
  });

  const storagePath = versionStoragePath(document.id, 1);
  await writeBlob(storagePath, input.bytes);

  await prisma.documentVersion.create({
    data: { documentId: document.id, versionNumber: 1, storagePath, hash },
  });

  return prisma.document.update({ where: { id: document.id }, data: { storagePath } });
}

/**
 * Supersedes a document with new bytes: current -> VERSIONED -> HASHED, and a new
 * DocumentVersion row. This is how an already-signed document gets signed again
 * (see the decisions log in PROGRESS.md).
 */
export async function addDocumentVersion(
  actor: Actor,
  documentId: string,
  filename: string,
  bytes: Uint8Array,
): Promise<Document> {
  requireCapability(actor, "document:upload");
  validateUpload({ filename, bytes });

  const document = await getDocumentOwnedBy(actor, documentId);
  const current = assertDocumentState(document.status);
  assertTransition(current, "VERSIONED");

  const latest = await prisma.documentVersion.findFirst({
    where: { documentId },
    orderBy: { versionNumber: "desc" },
  });
  const versionNumber = (latest?.versionNumber ?? 0) + 1;

  const hash = sha256Hex(bytes);
  if (latest?.hash === hash) {
    throw new ConflictError("These bytes are identical to the current version");
  }

  const storagePath = versionStoragePath(documentId, versionNumber);
  await writeBlob(storagePath, bytes);

  await prisma.documentVersion.create({
    data: { documentId, versionNumber, storagePath, hash },
  });

  return prisma.document.update({
    where: { id: documentId },
    data: {
      storagePath,
      currentHash: hash,
      status: assertPath(["VERSIONED", "HASHED"]),
    },
  });
}

export async function setDocumentState(
  documentId: string,
  to: DocumentState,
): Promise<Document> {
  const document = await prisma.document.findUnique({ where: { id: documentId } });
  if (!document) throw new NotFoundError("Document not found");

  assertTransition(assertDocumentState(document.status), to);
  return prisma.document.update({ where: { id: documentId }, data: { status: to } });
}

export async function listDocuments(actor: Actor) {
  requireCapability(actor, "document:read");
  return prisma.document.findMany({
    orderBy: { createdAt: "desc" },
    include: {
      owner: { select: { email: true } },
      versions: { orderBy: { versionNumber: "desc" } },
    },
  });
}

export async function getDocument(actor: Actor, documentId: string) {
  requireCapability(actor, "document:read");
  const document = await prisma.document.findUnique({
    where: { id: documentId },
    include: {
      owner: { select: { email: true } },
      versions: { orderBy: { versionNumber: "desc" } },
    },
  });
  if (!document) throw new NotFoundError("Document not found");
  return document;
}

async function getDocumentOwnedBy(actor: Actor, documentId: string): Promise<Document> {
  const document = await prisma.document.findUnique({ where: { id: documentId } });
  if (!document) throw new NotFoundError("Document not found");
  if (document.ownerUserId !== actor.userId && actor.role !== "ADMIN") {
    throw new ConflictError("Only the document owner or an ADMIN can add a version");
  }
  return document;
}

export async function latestVersion(documentId: string): Promise<DocumentVersion> {
  const version = await prisma.documentVersion.findFirst({
    where: { documentId },
    orderBy: { versionNumber: "desc" },
  });
  if (!version) throw new NotFoundError("Document has no versions");
  return version;
}

/**
 * Recomputes the SHA-256 of what is on disk right now. This is verification step 6
 * (Figure 8) and is deliberately not cached anywhere.
 */
export async function recomputeVersionHash(version: DocumentVersion): Promise<string> {
  return sha256Hex(await readBlob(version.storagePath));
}
