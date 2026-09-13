// Cryptographic Orchestration layer: the single entry point every other layer uses.
//
// Nothing outside lib/crypto imports a provider, the registry, or an algorithm library.
// Callers pass an algorithm identifier read from a record (certificate or signature) and
// receive plain results; they never branch on which algorithm it is.
import { registry, type Algorithm } from "@/lib/crypto/registry";
import type { AlgorithmMetadata, KeyPairPem, SignatureProvider } from "@/lib/crypto/types";

export type { Algorithm } from "@/lib/crypto/registry";
export type { AlgorithmMetadata, KeyPairPem } from "@/lib/crypto/types";

export const ALGORITHMS: readonly Algorithm[] = registry.algorithms;
export const isAlgorithm = registry.isAlgorithm;
export const assertAlgorithm = registry.assertAlgorithm;

export function providerFor(algorithm: Algorithm): SignatureProvider {
  return registry.providerFor(algorithm);
}

export type SignRequest = {
  algorithm: Algorithm;
  message: Uint8Array;
  privateKeyPem: string;
};

export type VerifyRequest = {
  algorithm: Algorithm;
  message: Uint8Array;
  signature: Uint8Array;
  publicKeyPem: string;
};

export const orchestrator = {
  algorithms: ALGORITHMS,

  describe(algorithm: Algorithm): AlgorithmMetadata {
    return providerFor(assertAlgorithm(algorithm)).metadata;
  },

  describeAll(): AlgorithmMetadata[] {
    return ALGORITHMS.map((algorithm) => providerFor(algorithm).metadata);
  },

  /** For identifiers read from storage: metadata when registered, null otherwise. Never throws. */
  lookup(value: string): AlgorithmMetadata | null {
    return isAlgorithm(value) ? providerFor(value).metadata : null;
  },

  /** A display label that stays safe for identifiers this installation does not support. */
  displayName(value: string): string {
    return orchestrator.lookup(value)?.displayName ?? `Unsupported algorithm (${value})`;
  },

  // Async so that an unregistered algorithm rejects rather than throwing synchronously:
  // callers get one error path, not two.
  async generateKeyPair(algorithm: Algorithm): Promise<KeyPairPem> {
    return providerFor(assertAlgorithm(algorithm)).generateKeyPair();
  },

  async sign({ algorithm, message, privateKeyPem }: SignRequest): Promise<Buffer> {
    return providerFor(assertAlgorithm(algorithm)).sign(message, privateKeyPem);
  },

  /** Returns false rather than throwing when a signature simply does not verify. */
  async verify({ algorithm, message, signature, publicKeyPem }: VerifyRequest): Promise<boolean> {
    return providerFor(assertAlgorithm(algorithm)).verify(message, signature, publicKeyPem);
  },

  /**
   * The algorithm a public key actually belongs to, decided by the key material rather than
   * by any label stored beside it. Null when no registered provider recognises it.
   */
  identifyPublicKey(publicKeyPem: string): Algorithm | null {
    const matches = ALGORITHMS.filter((algorithm) =>
      providerFor(algorithm).identifiesPublicKey(publicKeyPem),
    );
    if (matches.length > 1) {
      throw new Error(`Registry misconfiguration: key recognised by ${matches.join(" and ")}`);
    }
    return matches[0] ?? null;
  },
};
