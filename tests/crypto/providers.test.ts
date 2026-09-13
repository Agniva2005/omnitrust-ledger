import { createHash } from "node:crypto";
import { beforeAll, describe, expect, it } from "vitest";
import {
  ALGORITHMS,
  orchestrator,
  providerFor,
  type Algorithm,
  type KeyPairPem,
} from "@/lib/crypto/orchestrator";

const message = createHash("sha256").update("omnitrust ledger document").digest();
const otherMessage = createHash("sha256").update("a different document").digest();

const keys = {} as Record<Algorithm, KeyPairPem>;
const spare = {} as Record<Algorithm, KeyPairPem>;

beforeAll(async () => {
  for (const algorithm of ALGORITHMS) {
    keys[algorithm] = await orchestrator.generateKeyPair(algorithm);
    spare[algorithm] = await orchestrator.generateKeyPair(algorithm);
  }
}, 60_000);

describe.each(ALGORITHMS)("%s provider", (algorithm) => {
  const provider = providerFor(algorithm);

  it("declares itself under the algorithm it is registered as", () => {
    expect(provider.metadata.id).toBe(algorithm);
  });

  it("generates PKCS#8 / SubjectPublicKeyInfo PEM", () => {
    expect(keys[algorithm].privateKeyPem).toMatch(/^-----BEGIN PRIVATE KEY-----\n/);
    expect(keys[algorithm].privateKeyPem.trimEnd()).toMatch(/-----END PRIVATE KEY-----$/);
    expect(keys[algorithm].publicKeyPem).toMatch(/^-----BEGIN PUBLIC KEY-----\n/);
    expect(keys[algorithm].publicKeyPem.trimEnd()).toMatch(/-----END PUBLIC KEY-----$/);
  });

  it("generates a distinct key pair each time", () => {
    expect(keys[algorithm].privateKeyPem).not.toBe(spare[algorithm].privateKeyPem);
  });

  it("signs and verifies a message", async () => {
    const signature = await provider.sign(message, keys[algorithm].privateKeyPem);
    expect(await provider.verify(message, signature, keys[algorithm].publicKeyPem)).toBe(true);
  });

  it("rejects the signature against a different message", async () => {
    const signature = await provider.sign(message, keys[algorithm].privateKeyPem);
    expect(await provider.verify(otherMessage, signature, keys[algorithm].publicKeyPem)).toBe(false);
  });

  it("rejects a message with one bit flipped", async () => {
    const signature = await provider.sign(message, keys[algorithm].privateKeyPem);
    const altered = Buffer.from(message);
    altered[0] ^= 0x01;
    expect(await provider.verify(altered, signature, keys[algorithm].publicKeyPem)).toBe(false);
  });

  it("rejects a signature with one bit flipped", async () => {
    const signature = await provider.sign(message, keys[algorithm].privateKeyPem);
    const altered = Buffer.from(signature);
    altered[altered.length - 1] ^= 0x01;
    expect(await provider.verify(message, altered, keys[algorithm].publicKeyPem)).toBe(false);
  });

  it("rejects a truncated signature", async () => {
    const signature = await provider.sign(message, keys[algorithm].privateKeyPem);
    const truncated = signature.subarray(0, signature.length - 2);
    expect(await provider.verify(message, truncated, keys[algorithm].publicKeyPem)).toBe(false);
  });

  it("rejects the right signature against the wrong public key of the same algorithm", async () => {
    const signature = await provider.sign(message, keys[algorithm].privateKeyPem);
    expect(await provider.verify(message, signature, spare[algorithm].publicKeyPem)).toBe(false);
  });

  it("produces signatures within its declared size", async () => {
    const { fixedBytes, maxBytes } = provider.metadata.signature;
    for (let round = 0; round < 10; round += 1) {
      const signature = await provider.sign(message, keys[algorithm].privateKeyPem);
      if (fixedBytes !== null) expect(signature.length).toBe(fixedBytes);
      expect(signature.length).toBeLessThanOrEqual(maxBytes);
    }
  });

  it("behaves as its metadata says: deterministic or randomised", async () => {
    const a = await provider.sign(message, keys[algorithm].privateKeyPem);
    const b = await provider.sign(message, keys[algorithm].privateKeyPem);
    expect(a.equals(b)).toBe(provider.metadata.deterministic);
    expect(await provider.verify(message, a, keys[algorithm].publicKeyPem)).toBe(true);
    expect(await provider.verify(message, b, keys[algorithm].publicKeyPem)).toBe(true);
  });
});

describe("signature encodings match each algorithm's specification", () => {
  it("RSA-PSS 3072 produces exactly 384 bytes (modulus length)", async () => {
    const signature = await providerFor("RSA").sign(message, keys.RSA.privateKeyPem);
    expect(signature.length).toBe(384);
  });

  it("Ed25519 produces exactly 64 bytes (RFC 8032)", async () => {
    const signature = await providerFor("ED25519").sign(message, keys.ED25519.privateKeyPem);
    expect(signature.length).toBe(64);
  });

  it("ECDSA P-256 produces a DER SEQUENCE of two INTEGERs of at most 72 bytes", async () => {
    const signature = await providerFor("ECDSA_P256").sign(message, keys.ECDSA_P256.privateKeyPem);
    expect(signature[0]).toBe(0x30); // SEQUENCE
    expect(signature[1]).toBe(signature.length - 2); // declared length matches actual
    expect(signature[2]).toBe(0x02); // INTEGER r
    const rLength = signature[3];
    expect(signature[4 + rLength]).toBe(0x02); // INTEGER s
    expect(signature.length).toBeLessThanOrEqual(72);
  });
});

const ORDERED_PAIRS = ALGORITHMS.flatMap((provider) =>
  ALGORITHMS.filter((key) => key !== provider).map((key) => [provider, key] as const),
);

describe("provider-level algorithm confusion", () => {
  // Regression tests. Before providers checked key types, OpenSSL followed whatever key it
  // was handed: the RSA provider given an ECDSA key produced an ECDSA signature, and would
  // report a genuine ECDSA signature as a valid RSA-PSS one.
  it.each(ORDERED_PAIRS)("the %s provider refuses to sign with a %s private key", async (provider, key) => {
    await expect(providerFor(provider).sign(message, keys[key].privateKeyPem)).rejects.toThrow();
  });

  it.each(ORDERED_PAIRS)(
    "the %s provider refuses a genuine %s signature presented with that algorithm's own public key",
    async (provider, key) => {
      const genuine = await providerFor(key).sign(message, keys[key].privateKeyPem);
      expect(await providerFor(key).verify(message, genuine, keys[key].publicKeyPem)).toBe(true);

      const outcome = await providerFor(provider)
        .verify(message, genuine, keys[key].publicKeyPem)
        .catch(() => "refused" as const);
      expect(outcome).toBe("refused");
    },
  );
});

describe("cross-algorithm substitution", () => {
  it("a signature made under one algorithm never verifies under another", async () => {
    for (const signingAlgorithm of ALGORITHMS) {
      const signature = await orchestrator.sign({
        algorithm: signingAlgorithm,
        message,
        privateKeyPem: keys[signingAlgorithm].privateKeyPem,
      });

      for (const verifyingAlgorithm of ALGORITHMS) {
        if (verifyingAlgorithm === signingAlgorithm) continue;

        // Either a clean false, or a thrown "that is not my kind of key" -- both are
        // correct refusals. The verification workflow refuses before reaching this point,
        // by comparing the key's own algorithm with the signature record.
        const outcome = await orchestrator
          .verify({
            algorithm: verifyingAlgorithm,
            message,
            signature,
            publicKeyPem: keys[verifyingAlgorithm].publicKeyPem,
          })
          .catch(() => "threw" as const);

        expect(outcome).not.toBe(true);
      }
    }
  });
});
