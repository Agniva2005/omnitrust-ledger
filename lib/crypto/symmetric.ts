import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { loadMasterKey } from "@/lib/crypto/key-custody";

const ALGORITHM = "aes-256-gcm";
const IV_BYTES = 12;
const TAG_BYTES = 16;

/**
 * Raised when AES-GCM rejects the authentication tag, i.e. the stored bytes are
 * not the bytes that were written. Callers surface this as tamper evidence
 * rather than as an internal error.
 */
export class DecryptionIntegrityError extends Error {
  constructor(message = "Authenticated decryption failed: stored bytes have been altered") {
    super(message);
    this.name = "DecryptionIntegrityError";
  }
}

let cachedKey: Buffer | null = null;

export function masterKeyPath(): string {
  return path.resolve(process.env.MASTER_KEY_PATH ?? "./storage/keys/master.key");
}

/**
 * Demo-grade key management: the data-encryption key is a local file, not an HSM or KMS. The
 * file may be plaintext or wrapped under a passphrase or Windows DPAPI (lib/crypto/key-custody.ts).
 * Stated as a limitation in README.md and in the UI footer.
 */
export function masterKey(): Buffer {
  if (cachedKey) return cachedKey;

  const keyPath = masterKeyPath();
  if (!fs.existsSync(keyPath)) {
    throw new Error(`Master key not found at ${keyPath}. Run \`npm run setup\`.`);
  }

  cachedKey = loadMasterKey(keyPath);
  return cachedKey;
}

export function resetMasterKeyCache() {
  cachedKey = null;
}

/** Returns iv | tag | ciphertext as a single buffer. */
export function encrypt(plaintext: Uint8Array): Buffer {
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(ALGORITHM, masterKey(), iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), ciphertext]);
}

export function decrypt(bundle: Uint8Array): Buffer {
  const buffer = Buffer.from(bundle);
  if (buffer.length < IV_BYTES + TAG_BYTES) {
    throw new DecryptionIntegrityError("Ciphertext is too short to be well-formed");
  }

  const iv = buffer.subarray(0, IV_BYTES);
  const tag = buffer.subarray(IV_BYTES, IV_BYTES + TAG_BYTES);
  const ciphertext = buffer.subarray(IV_BYTES + TAG_BYTES);

  const decipher = createDecipheriv(ALGORITHM, masterKey(), iv);
  decipher.setAuthTag(tag);
  try {
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new DecryptionIntegrityError();
  }
}

/** Convenience wrappers for the encrypted private-key columns. */
export function encryptString(plaintext: string): string {
  return encrypt(Buffer.from(plaintext, "utf8")).toString("base64");
}

export function decryptString(bundle: string): string {
  return decrypt(Buffer.from(bundle, "base64")).toString("utf8");
}
