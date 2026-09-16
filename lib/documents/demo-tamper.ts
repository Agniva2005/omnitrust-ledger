// Demonstration-only tampering, for showing detection live.
//
// Nothing here weakens a control or fakes a verdict: it performs the alteration an attacker
// with storage or database access would perform, and leaves the verifier to notice. The
// point of the application is that these alterations are caught, so producing one on demand
// is how that claim is shown rather than asserted. Every action is written to the audit log,
// and the original bytes are kept so the document can be put back exactly as it was.
//
// This exists because the application is explicitly a demonstration build. A production
// system would have no such route, which is why it sits behind its own ADMIN-only capability.
import fs from "node:fs/promises";
import path from "node:path";
import { appendAuditEntry } from "@/lib/audit/log";
import { requireCapability, type Actor } from "@/lib/auth/rbac";
import { sha256Hex } from "@/lib/crypto/hash";
import { ConflictError, NotFoundError } from "@/lib/api";
import { prisma } from "@/lib/db";
import { absolutePath, readBlob, storageRoot, writeBlob } from "@/lib/documents/storage";

export type TamperState = {
  contentAltered: boolean;
  signatureAltered: boolean;
  canRestoreContent: boolean;
  canRestoreSignature: boolean;
  signedHash: string;
  storedHash: string | null;
  storedHashError: string | null;
};

function backupDir(documentId: string): string {
  return path.join(storageRoot(), "demo-tamper", documentId);
}

function contentBackup(documentId: string, versionNumber: number): string {
  return path.join(backupDir(documentId), `v${versionNumber}.bin`);
}

function signatureBackup(documentId: string, versionNumber: number): string {
  return path.join(backupDir(documentId), `v${versionNumber}.sig`);
}

async function exists(target: string): Promise<boolean> {
  try {
    await fs.access(target);
    return true;
  } catch {
    return false;
  }
}

async function latestVersion(documentId: string) {
  const version = await prisma.documentVersion.findFirst({
    where: { documentId },
    orderBy: { versionNumber: "desc" },
    include: { signatures: true },
  });
  if (!version) throw new NotFoundError("Document version not found");
  return version;
}

/**
 * Hash of the bytes actually on disk right now, or the reason they could not be read.
 * A flipped ciphertext byte fails the AES-GCM tag, so reading is itself a tamper check.
 */
async function storedHashOf(storagePath: string): Promise<{ hash: string | null; error: string | null }> {
  try {
    return { hash: sha256Hex(await readBlob(storagePath)), error: null };
  } catch (error) {
    return { hash: null, error: error instanceof Error ? error.message : "unreadable" };
  }
}

export async function tamperState(documentId: string): Promise<TamperState> {
  const version = await latestVersion(documentId);
  const signature = version.signatures[0];
  const { hash, error } = await storedHashOf(version.storagePath);

  const canRestoreContent = await exists(contentBackup(documentId, version.versionNumber));
  const canRestoreSignature = await exists(signatureBackup(documentId, version.versionNumber));

  return {
    contentAltered: hash !== version.hash,
    signatureAltered: canRestoreSignature && Boolean(signature),
    canRestoreContent,
    canRestoreSignature,
    signedHash: version.hash,
    storedHash: hash,
    storedHashError: error,
  };
}

/**
 * Replaces the stored bytes with different, validly encrypted content while leaving the
 * recorded hash — the one the signature attests to — untouched. This is the attacker who
 * reached the storage layer but cannot forge a signature.
 */
export async function tamperContent(
  actor: Actor,
  documentId: string,
  bytes: Uint8Array,
): Promise<TamperState> {
  requireCapability(actor, "demo:tamper");
  const version = await latestVersion(documentId);

  if (bytes.byteLength === 0) throw new ConflictError("Replacement file is empty");
  if (sha256Hex(bytes) === version.hash) {
    throw new ConflictError("These bytes are identical to the signed version, so nothing would change");
  }

  // Keep the first original only: tampering twice must not overwrite the good copy.
  const backup = contentBackup(documentId, version.versionNumber);
  await fs.mkdir(path.dirname(backup), { recursive: true });
  if (!(await exists(backup))) {
    await fs.copyFile(absolutePath(version.storagePath), backup);
  }

  await writeBlob(version.storagePath, bytes);

  await appendAuditEntry({
    actorUserId: actor.userId,
    action: "DEMO_CONTENT_TAMPERED",
    targetType: "DocumentVersion",
    targetId: version.id,
    metadata: {
      documentId,
      versionNumber: version.versionNumber,
      signedHash: version.hash,
      storedHashAfter: sha256Hex(bytes),
      byteLength: bytes.byteLength,
    },
  });

  return tamperState(documentId);
}

/** Flips one bit of the encrypted blob, which the AES-GCM tag refuses on read. */
export async function tamperCiphertext(actor: Actor, documentId: string): Promise<TamperState> {
  requireCapability(actor, "demo:tamper");
  const version = await latestVersion(documentId);

  const target = absolutePath(version.storagePath);
  const backup = contentBackup(documentId, version.versionNumber);
  await fs.mkdir(path.dirname(backup), { recursive: true });
  if (!(await exists(backup))) await fs.copyFile(target, backup);

  const blob = await fs.readFile(target);
  // Last byte is ciphertext, never the iv or the tag, so the failure is the tag rejecting it.
  blob[blob.length - 1] = blob[blob.length - 1] ^ 0x01;
  await fs.writeFile(target, blob);

  await appendAuditEntry({
    actorUserId: actor.userId,
    action: "DEMO_CIPHERTEXT_TAMPERED",
    targetType: "DocumentVersion",
    targetId: version.id,
    metadata: { documentId, versionNumber: version.versionNumber, byteOffset: blob.length - 1 },
  });

  return tamperState(documentId);
}

/** Flips one bit of the stored signature, leaving its length a valid one for the algorithm. */
export async function tamperSignature(actor: Actor, documentId: string): Promise<TamperState> {
  requireCapability(actor, "demo:tamper");
  const version = await latestVersion(documentId);
  const signature = version.signatures[0];
  if (!signature) throw new ConflictError("This version has no signature to alter");

  const original = Buffer.from(signature.signatureBytes);
  const backup = signatureBackup(documentId, version.versionNumber);
  await fs.mkdir(path.dirname(backup), { recursive: true });
  if (!(await exists(backup))) await fs.writeFile(backup, original);

  const altered = Buffer.from(original);
  altered[0] = altered[0] ^ 0x01;
  await prisma.signature.update({
    where: { id: signature.id },
    data: { signatureBytes: altered },
  });

  await appendAuditEntry({
    actorUserId: actor.userId,
    action: "DEMO_SIGNATURE_TAMPERED",
    targetType: "Signature",
    targetId: signature.id,
    metadata: {
      documentId,
      versionNumber: version.versionNumber,
      algorithm: signature.algorithm,
      byteLength: altered.length,
      firstBytesBefore: original.subarray(0, 4).toString("hex"),
      firstBytesAfter: altered.subarray(0, 4).toString("hex"),
    },
  });

  return tamperState(documentId);
}

/** Puts back the exact bytes kept before the first alteration. */
export async function restoreTamper(actor: Actor, documentId: string): Promise<TamperState> {
  requireCapability(actor, "demo:tamper");
  const version = await latestVersion(documentId);
  const signature = version.signatures[0];

  const restored: string[] = [];

  const blobBackup = contentBackup(documentId, version.versionNumber);
  if (await exists(blobBackup)) {
    await fs.copyFile(blobBackup, absolutePath(version.storagePath));
    await fs.rm(blobBackup);
    restored.push("content");
  }

  const sigBackup = signatureBackup(documentId, version.versionNumber);
  if (signature && (await exists(sigBackup))) {
    await prisma.signature.update({
      where: { id: signature.id },
      data: { signatureBytes: await fs.readFile(sigBackup) },
    });
    await fs.rm(sigBackup);
    restored.push("signature");
  }

  if (restored.length === 0) throw new ConflictError("Nothing to restore: this document has not been altered");

  await appendAuditEntry({
    actorUserId: actor.userId,
    action: "DEMO_TAMPER_RESTORED",
    targetType: "DocumentVersion",
    targetId: version.id,
    metadata: { documentId, versionNumber: version.versionNumber, restored: restored.join(", ") },
  });

  return tamperState(documentId);
}
