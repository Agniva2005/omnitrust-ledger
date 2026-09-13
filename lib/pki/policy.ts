// PKI policy. This is the one module outside lib/crypto permitted to name an algorithm,
// because which registered algorithm the local CA signs with is a policy choice rather
// than algorithm-specific logic. scripts/check-crypto-boundary.ts allowlists this file.
import type { Algorithm } from "@/lib/crypto/orchestrator";

/**
 * The root CA signs certificates for subjects of every algorithm, so its own algorithm is
 * independent of theirs. P-256 keeps the size differences between issued certificates
 * attributable to the subject's key rather than swamped by a large issuer signature.
 */
export const CA_ALGORITHM: Algorithm = "ECDSA_P256";
