import { createHash } from "node:crypto";

export const HASH_ALGORITHM = "SHA-256";

/**
 * The one SHA-256 implementation in the codebase. Document hashing (Phase 2), the
 * signature digest (Phase 5) and the audit hash chain (Phase 7) all call through
 * here, so that hashing stays inside the Cryptographic layer per Section 2 rule 2.
 */
export function sha256(data: Uint8Array | string): Buffer {
  return createHash("sha256").update(data).digest();
}

export function sha256Hex(data: Uint8Array | string): string {
  return sha256(data).toString("hex");
}
