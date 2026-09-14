// PKI policy. This is the one module outside lib/crypto permitted to name an algorithm,
// because which registered algorithm each trust service signs with is a policy choice rather
// than algorithm-specific logic. scripts/check-crypto-boundary.ts allowlists this file.
//
// Each default below can be overridden per installation with an environment variable, so a
// whole trust chain can move to a post-quantum or hybrid algorithm without a code change. The
// choice binds when a service is first created: an existing CA, Time-Stamp Authority or audit
// signer keeps the algorithm recorded on its row, whatever the variable says later.
import { isAlgorithm, orchestrator, type Algorithm } from "@/lib/crypto/orchestrator";

/**
 * Default for the root CA. The CA signs certificates for subjects of every algorithm, so its own
 * algorithm is independent of theirs. P-256 keeps the size differences between issued certificates
 * attributable to the subject's key rather than swamped by a large issuer signature.
 */
export const CA_ALGORITHM: Algorithm = "ECDSA_P256";

/**
 * Default for the local Time-Stamp Authority. ECDSA P-256 keeps tokens small, and the OpenSSL
 * command-line tool can verify the resulting tokens independently.
 */
export const TSA_ALGORITHM: Algorithm = "ECDSA_P256";

/**
 * Default for the audit-log checkpoint signer. A separate key from the CA and the TSA; P-256
 * keeps checkpoints small and lets the OpenSSL command-line tool verify them independently.
 */
export const AUDIT_SIGNER_ALGORITHM: Algorithm = "ECDSA_P256";

/** The environment variables that override the defaults above. */
export const PKI_POLICY_VARIABLES = {
  ca: "PKI_CA_ALGORITHM",
  tsa: "PKI_TSA_ALGORITHM",
  auditSigner: "PKI_AUDIT_SIGNER_ALGORITHM",
} as const;

export class PkiPolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PkiPolicyError";
  }
}

function configured(variable: string, fallback: Algorithm, mustIssueCertificates: boolean): Algorithm {
  const value = process.env[variable]?.trim();
  if (!value) return fallback;
  if (!isAlgorithm(value)) {
    throw new PkiPolicyError(`${variable}="${value}" is not a registered algorithm (registered: ${orchestrator.algorithms.join(", ")})`);
  }
  const metadata = orchestrator.describe(value);
  if (!metadata.capabilities.generateKeyPair || !metadata.capabilities.sign) {
    throw new PkiPolicyError(`${variable}="${value}": ${metadata.displayName} cannot generate keys and sign in this installation`);
  }
  if (mustIssueCertificates && !metadata.capabilities.x509Issuer) {
    throw new PkiPolicyError(`${variable}="${value}": ${metadata.displayName} cannot sign X.509 certificates in this installation`);
  }
  return value;
}

/** The algorithm a newly created root CA signs with. It must be able to sign certificates and CRLs. */
export function caAlgorithm(): Algorithm {
  return configured(PKI_POLICY_VARIABLES.ca, CA_ALGORITHM, true);
}

/** The algorithm a newly created Time-Stamp Authority signs tokens with. Tokens are CMS, so any signing algorithm works. */
export function tsaAlgorithm(): Algorithm {
  return configured(PKI_POLICY_VARIABLES.tsa, TSA_ALGORITHM, false);
}

/** The algorithm a newly created audit signer signs checkpoints with. */
export function auditSignerAlgorithm(): Algorithm {
  return configured(PKI_POLICY_VARIABLES.auditSigner, AUDIT_SIGNER_ALGORITHM, false);
}
