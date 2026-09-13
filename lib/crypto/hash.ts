import { createHash } from "node:crypto";

export const HASH_ALGORITHM = "SHA-256";

/** Digest algorithm OIDs (NIST CSOR) used in CMS and time-stamp structures. */
export const DIGEST_OIDS = {
  sha256: "2.16.840.1.101.3.4.2.1",
  sha512: "2.16.840.1.101.3.4.2.3",
} as const;

const DIGESTS: Record<string, { name: string; bytes: number }> = {
  [DIGEST_OIDS.sha256]: { name: "sha256", bytes: 32 },
  [DIGEST_OIDS.sha512]: { name: "sha512", bytes: 64 },
};

/**
 * The one SHA-256 implementation in the codebase. Document hashing, the signature message
 * and the audit hash chain all call through here, so hashing stays inside the
 * Cryptographic layer.
 */
export function sha256(data: Uint8Array | string): Buffer {
  return createHash("sha256").update(data).digest();
}

export function sha256Hex(data: Uint8Array | string): string {
  return sha256(data).toString("hex");
}

export function isSupportedDigestOid(oid: string): boolean {
  return Object.hasOwn(DIGESTS, oid);
}

/** Output length of a supported digest, or null. */
export function digestLength(oid: string): number | null {
  return isSupportedDigestOid(oid) ? DIGESTS[oid].bytes : null;
}

export function digestByOid(oid: string, data: Uint8Array): Buffer {
  if (!isSupportedDigestOid(oid)) throw new Error(`Unsupported digest algorithm ${oid}`);
  return createHash(DIGESTS[oid].name).update(data).digest();
}
