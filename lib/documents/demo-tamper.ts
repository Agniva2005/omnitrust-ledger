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
import { ALGORITHMS } from "@/lib/crypto/orchestrator";
import { ConflictError, NotFoundError } from "@/lib/api";
import { prisma } from "@/lib/db";
import { absolutePath, readBlob, storageRoot, writeBlob } from "@/lib/documents/storage";

export type TamperState = {
  contentAltered: boolean;
  signatureAltered: boolean;
  canRestoreContent: boolean;
  canRestoreSignature: boolean;
  /** Which alteration was applied to the signature record, for the interface to name. */
  alteration: string | null;
  signedHash: string;
  storedHash: string | null;
  storedHashError: string | null;
};

/**
 * Everything an attack on the signature record can change, captured before the first one.
 * The certificate is included because relabelling an algorithm changes that row too.
 */
type SignatureSnapshot = {
  alteration: string;
  signatureId: string;
  signatureBytes: string;
  certificateId: string;
  algorithm: string;
  timestampToken: string | null;
  timestampedAt: string | null;
  cmsSignature: string | null;
  certificate: { id: string; algorithm: string };
};

function backupDir(documentId: string): string {
  return path.join(storageRoot(), "demo-tamper", documentId);
}

function contentBackup(documentId: string, versionNumber: number): string {
  return path.join(backupDir(documentId), `v${versionNumber}.bin`);
}

function signatureBackup(documentId: string, versionNumber: number): string {
  return path.join(backupDir(documentId), `v${versionNumber}.signature.json`);
}

async function readSignatureSnapshot(documentId: string, versionNumber: number): Promise<SignatureSnapshot | null> {
  try {
    return JSON.parse(await fs.readFile(signatureBackup(documentId, versionNumber), "utf8")) as SignatureSnapshot;
  } catch {
    return null;
  }
}

type SignatureRow = {
  id: string;
  signatureBytes: Uint8Array;
  certificateId: string;
  algorithm: string;
  timestampToken: Uint8Array | null;
  timestampedAt: Date | null;
  cmsSignature: Uint8Array | null;
};

/** Keeps the first snapshot only, so a second attack cannot overwrite the good copy. */
async function keepSignatureSnapshot(documentId: string, versionNumber: number, signature: SignatureRow, alteration: string): Promise<void> {
  const target = signatureBackup(documentId, versionNumber);
  if (await readSignatureSnapshot(documentId, versionNumber)) return;

  const certificate = await prisma.certificate.findUniqueOrThrow({ where: { id: signature.certificateId } });
  const snapshot: SignatureSnapshot = {
    alteration,
    signatureId: signature.id,
    signatureBytes: Buffer.from(signature.signatureBytes).toString("hex"),
    certificateId: signature.certificateId,
    algorithm: signature.algorithm,
    timestampToken: signature.timestampToken ? Buffer.from(signature.timestampToken).toString("hex") : null,
    timestampedAt: signature.timestampedAt?.toISOString() ?? null,
    cmsSignature: signature.cmsSignature ? Buffer.from(signature.cmsSignature).toString("hex") : null,
    certificate: { id: certificate.id, algorithm: certificate.algorithm },
  };
  await fs.mkdir(path.dirname(target), { recursive: true });
  await fs.writeFile(target, JSON.stringify(snapshot, null, 2));
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
  const snapshot = await readSignatureSnapshot(documentId, version.versionNumber);
  const canRestoreSignature = snapshot !== null;

  return {
    contentAltered: hash !== version.hash,
    signatureAltered: canRestoreSignature && Boolean(signature),
    canRestoreContent,
    canRestoreSignature,
    alteration: snapshot?.alteration ?? null,
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
  await keepSignatureSnapshot(documentId, version.versionNumber, signature, "a flipped signature bit");

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

/** A signature on some other document made under the same certificate, for the replay attacks. */
async function siblingSignature(documentId: string, certificateId: string) {
  return prisma.signature.findFirst({
    where: { certificateId, documentVersion: { documentId: { not: documentId } } },
    include: { documentVersion: { include: { document: { select: { filename: true } } } } },
    orderBy: { signedAt: "desc" },
  });
}

/**
 * Copies a genuine signature from another document onto this one. Both were made by the same
 * certificate, so nothing about the identity is wrong — only that the signature covers a
 * different document's hash.
 */
export async function tamperReplay(actor: Actor, documentId: string): Promise<TamperState> {
  requireCapability(actor, "demo:tamper");
  const version = await latestVersion(documentId);
  const signature = version.signatures[0];
  if (!signature) throw new ConflictError("This version has no signature to replace");

  const sibling = await siblingSignature(documentId, signature.certificateId);
  if (!sibling) {
    throw new ConflictError("Replay needs a second document signed by the same certificate; there is none, so sign another document with it first");
  }

  await keepSignatureSnapshot(documentId, version.versionNumber, signature, `a signature replayed from ${sibling.documentVersion.document.filename}`);
  await prisma.signature.update({
    where: { id: signature.id },
    data: { signatureBytes: sibling.signatureBytes, timestampToken: sibling.timestampToken, timestampedAt: sibling.timestampedAt },
  });

  await appendAuditEntry({
    actorUserId: actor.userId,
    action: "DEMO_SIGNATURE_TAMPERED",
    targetType: "Signature",
    targetId: signature.id,
    metadata: { documentId, versionNumber: version.versionNumber, style: "replay", from: sibling.documentVersion.document.filename },
  });
  return tamperState(documentId);
}

/**
 * Relabels the signature and its certificate as a different algorithm, without re-signing
 * anything: the records claim one algorithm while the key and signature are another's.
 */
export async function tamperAlgorithmLabel(actor: Actor, documentId: string): Promise<TamperState> {
  requireCapability(actor, "demo:tamper");
  const version = await latestVersion(documentId);
  const signature = version.signatures[0];
  if (!signature) throw new ConflictError("This version has no signature to relabel");

  const relabelled = ALGORITHMS.find((candidate) => candidate !== signature.algorithm);
  if (!relabelled) throw new ConflictError("Relabelling needs a second registered algorithm");

  await keepSignatureSnapshot(documentId, version.versionNumber, signature, `a signature relabelled as ${relabelled}`);
  await prisma.signature.update({ where: { id: signature.id }, data: { algorithm: relabelled } });
  await prisma.certificate.update({ where: { id: signature.certificateId }, data: { algorithm: relabelled } });

  await appendAuditEntry({
    actorUserId: actor.userId,
    action: "DEMO_SIGNATURE_TAMPERED",
    targetType: "Signature",
    targetId: signature.id,
    metadata: { documentId, versionNumber: version.versionNumber, style: "algorithm relabel", from: signature.algorithm, to: relabelled },
  });
  return tamperState(documentId);
}

/** Points the signature at somebody else's certificate, leaving the signature bytes alone. */
export async function tamperKeySubstitution(actor: Actor, documentId: string): Promise<TamperState> {
  requireCapability(actor, "demo:tamper");
  const version = await latestVersion(documentId);
  const signature = version.signatures[0];
  if (!signature) throw new ConflictError("This version has no signature to re-point");

  const substitute = await prisma.certificate.findFirst({
    where: { id: { not: signature.certificateId }, status: "ACTIVE" },
    orderBy: { issuedAt: "desc" },
  });
  if (!substitute) throw new ConflictError("Key substitution needs a second active certificate; issue one first");

  await keepSignatureSnapshot(documentId, version.versionNumber, signature, `the signature pointed at certificate ${substitute.serialNumber.slice(0, 12)}…`);
  await prisma.signature.update({ where: { id: signature.id }, data: { certificateId: substitute.id } });

  await appendAuditEntry({
    actorUserId: actor.userId,
    action: "DEMO_SIGNATURE_TAMPERED",
    targetType: "Signature",
    targetId: signature.id,
    metadata: { documentId, versionNumber: version.versionNumber, style: "key substitution", certificateSerial: substitute.serialNumber },
  });
  return tamperState(documentId);
}

/** Swaps the RFC 3161 token for one issued over a different signature value. */
export async function tamperTimestampSwap(actor: Actor, documentId: string): Promise<TamperState> {
  requireCapability(actor, "demo:tamper");
  const version = await latestVersion(documentId);
  const signature = version.signatures[0];
  if (!signature) throw new ConflictError("This version has no signature");
  if (!signature.timestampToken) throw new ConflictError("This signature has no time-stamp to swap");

  const donor = await prisma.signature.findFirst({
    where: { id: { not: signature.id }, timestampToken: { not: null } },
    include: { documentVersion: { include: { document: { select: { filename: true } } } } },
    orderBy: { signedAt: "desc" },
  });
  if (!donor?.timestampToken) throw new ConflictError("There is no other time-stamped signature to take a token from");

  await keepSignatureSnapshot(documentId, version.versionNumber, signature, `a time-stamp taken from ${donor.documentVersion.document.filename}`);
  await prisma.signature.update({
    where: { id: signature.id },
    data: { timestampToken: donor.timestampToken, timestampedAt: donor.timestampedAt },
  });

  await appendAuditEntry({
    actorUserId: actor.userId,
    action: "DEMO_SIGNATURE_TAMPERED",
    targetType: "Signature",
    targetId: signature.id,
    metadata: { documentId, versionNumber: version.versionNumber, style: "time-stamp swap", from: donor.documentVersion.document.filename },
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

  const snapshot = await readSignatureSnapshot(documentId, version.versionNumber);
  if (signature && snapshot) {
    await prisma.signature.update({
      where: { id: snapshot.signatureId },
      data: {
        signatureBytes: Buffer.from(snapshot.signatureBytes, "hex"),
        certificateId: snapshot.certificateId,
        algorithm: snapshot.algorithm,
        timestampToken: snapshot.timestampToken ? Buffer.from(snapshot.timestampToken, "hex") : null,
        timestampedAt: snapshot.timestampedAt ? new Date(snapshot.timestampedAt) : null,
        cmsSignature: snapshot.cmsSignature ? Buffer.from(snapshot.cmsSignature, "hex") : null,
      },
    });
    // Relabelling an algorithm changes the certificate row too, so that goes back as well.
    await prisma.certificate.update({ where: { id: snapshot.certificate.id }, data: { algorithm: snapshot.certificate.algorithm } });
    await fs.rm(signatureBackup(documentId, version.versionNumber));
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
