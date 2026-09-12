// Cryptographic Orchestration layer.
//
// The single entry point every other layer uses for signing and verification.
// Adding a fourth algorithm means adding one provider file and one registry line
// below; no other file in the codebase changes.
import { ecdsaProvider } from "@/lib/crypto/providers/ecdsa";
import { eddsaProvider } from "@/lib/crypto/providers/eddsa";
import { rsaProvider } from "@/lib/crypto/providers/rsa";
import {
  ALGORITHMS,
  assertAlgorithm,
  type Algorithm,
  type KeyPairPem,
  type SignatureProvider,
} from "@/lib/crypto/types";

const REGISTRY: Record<Algorithm, SignatureProvider> = {
  RSA: rsaProvider,
  ECDSA_P256: ecdsaProvider,
  ED25519: eddsaProvider,
};

export function providerFor(algorithm: Algorithm): SignatureProvider {
  const provider = REGISTRY[algorithm];
  if (!provider) throw new Error(`No signature provider registered for ${algorithm}`);
  return provider;
}

export type SignRequest = {
  algorithm: Algorithm;
  digest: Uint8Array;
  privateKeyPem: string;
};

export type VerifyRequest = {
  algorithm: Algorithm;
  digest: Uint8Array;
  signature: Uint8Array;
  publicKeyPem: string;
};

export const orchestrator = {
  algorithms: ALGORITHMS,

  /** Provider metadata for the UI and the benchmark table. */
  describe(algorithm: Algorithm) {
    const provider = providerFor(algorithm);
    return {
      algorithm: provider.algorithm,
      displayName: provider.displayName,
      description: provider.description,
      signatureByteLength: provider.signatureByteLength,
    };
  },

  describeAll() {
    return ALGORITHMS.map((algorithm) => orchestrator.describe(algorithm));
  },

  // These are async rather than Promise-returning so that an unregistered algorithm
  // rejects instead of throwing synchronously: callers get one error path, not two.
  async generateKeyPair(algorithm: Algorithm): Promise<KeyPairPem> {
    return providerFor(assertAlgorithm(algorithm)).generateKeyPair();
  },

  async sign({ algorithm, digest, privateKeyPem }: SignRequest): Promise<Buffer> {
    return providerFor(assertAlgorithm(algorithm)).sign(digest, privateKeyPem);
  },

  /**
   * Resolves the algorithm from the caller's record (certificate or signature row),
   * never from a hard-coded default, and returns false rather than throwing when a
   * signature simply does not verify.
   */
  async verify({ algorithm, digest, signature, publicKeyPem }: VerifyRequest): Promise<boolean> {
    return providerFor(assertAlgorithm(algorithm)).verify(digest, signature, publicKeyPem);
  },

  webCryptoParams(algorithm: Algorithm) {
    return providerFor(assertAlgorithm(algorithm)).webCrypto;
  },
};
