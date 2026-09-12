// Secure Storage layer. Persists blobs and nothing else: it makes no decision
// about which algorithm or key to use, it only calls the Cryptographic layer.
import fs from "node:fs/promises";
import path from "node:path";
import { decrypt, encrypt } from "@/lib/crypto/symmetric";

export function storageRoot(): string {
  return path.resolve(process.env.STORAGE_ROOT ?? "./storage");
}

export function documentsRoot(): string {
  return path.join(storageRoot(), "documents");
}

/** Relative path recorded in the database; resolved against the storage root on read. */
export function versionStoragePath(documentId: string, versionNumber: number): string {
  return path.posix.join("documents", documentId, `v${versionNumber}.bin`);
}

export function absolutePath(relativePath: string): string {
  const resolved = path.resolve(storageRoot(), relativePath);
  // Defence against a traversal-shaped storagePath ever reaching this function.
  if (resolved !== storageRoot() && !resolved.startsWith(storageRoot() + path.sep)) {
    throw new Error(`Refusing to access a path outside the storage root: ${relativePath}`);
  }
  return resolved;
}

/** Encrypts with AES-256-GCM and writes. Blobs are encrypted at rest per Section 3. */
export async function writeBlob(relativePath: string, plaintext: Uint8Array): Promise<void> {
  const target = absolutePath(relativePath);
  await fs.mkdir(path.dirname(target), { recursive: true });
  await fs.writeFile(target, encrypt(plaintext));
}

/**
 * Reads and authenticates a blob. Throws DecryptionIntegrityError if the bytes on
 * disk were altered after they were written (AES-GCM tag mismatch).
 */
export async function readBlob(relativePath: string): Promise<Buffer> {
  return decrypt(await fs.readFile(absolutePath(relativePath)));
}

export async function blobExists(relativePath: string): Promise<boolean> {
  try {
    await fs.access(absolutePath(relativePath));
    return true;
  } catch {
    return false;
  }
}

export async function storedByteLength(relativePath: string): Promise<number> {
  return (await fs.stat(absolutePath(relativePath))).size;
}
