// The provider registry.
//
// Adding an algorithm is one provider file under lib/crypto/providers/ plus one entry in
// PROVIDERS. The Algorithm type, the list of algorithms, API validation, certificate
// issuance, signing, verification, the seed data and every UI list are derived from this
// object, and tests/crypto/agility.test.ts proves it with a provider this file does not
// contain.
import { ecdsaProvider } from "@/lib/crypto/providers/ecdsa";
import { eddsaProvider } from "@/lib/crypto/providers/eddsa";
import { mlDsa65Provider } from "@/lib/crypto/providers/mldsa";
import { rsaProvider } from "@/lib/crypto/providers/rsa";
import type { SignatureProvider } from "@/lib/crypto/types";

export const PROVIDERS = {
  RSA: rsaProvider,
  ECDSA_P256: ecdsaProvider,
  ED25519: eddsaProvider,
  ML_DSA_65: mlDsa65Provider,
} as const satisfies Record<string, SignatureProvider>;

export type Algorithm = keyof typeof PROVIDERS;

export function createRegistry<Registry extends Record<string, SignatureProvider>>(
  providers: Registry,
) {
  type Id = Extract<keyof Registry, string>;

  const ids = Object.keys(providers) as Id[];
  if (ids.length === 0) throw new Error("The provider registry is empty");

  for (const id of ids) {
    const provider = providers[id];
    if (provider.metadata.id !== id) {
      throw new Error(`Provider registered as ${id} declares itself as ${provider.metadata.id}`);
    }
    if ((provider.certificateSigning !== null) !== provider.metadata.capabilities.x509Issuer) {
      throw new Error(`Provider ${id}: certificateSigning must be present exactly when x509Issuer is true`);
    }
  }

  function isAlgorithm(value: unknown): value is Id {
    return typeof value === "string" && Object.hasOwn(providers, value);
  }

  return {
    algorithms: ids as readonly Id[],
    isAlgorithm,
    assertAlgorithm(value: unknown): Id {
      if (!isAlgorithm(value)) throw new Error(`Unsupported algorithm: ${String(value)}`);
      return value;
    },
    providerFor(algorithm: Id): SignatureProvider {
      if (!isAlgorithm(algorithm)) throw new Error(`No signature provider registered for ${algorithm}`);
      return providers[algorithm];
    },
  };
}

export const registry = createRegistry(PROVIDERS);
