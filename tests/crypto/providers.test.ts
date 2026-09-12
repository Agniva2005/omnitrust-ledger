import { createHash } from "node:crypto";
import { beforeAll, describe, expect, it } from "vitest";
import { orchestrator, providerFor } from "@/lib/crypto/orchestrator";
import { ALGORITHMS, type Algorithm, type KeyPairPem } from "@/lib/crypto/types";

const digest = createHash("sha256").update("omnitrust ledger document").digest();
const otherDigest = createHash("sha256").update("a different document").digest();

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
    expect(provider.algorithm).toBe(algorithm);
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

  it("signs and verifies a digest", async () => {
    const signature = await provider.sign(digest, keys[algorithm].privateKeyPem);
    expect(await provider.verify(digest, signature, keys[algorithm].publicKeyPem)).toBe(true);
  });

  it("rejects the signature against a different digest", async () => {
    const signature = await provider.sign(digest, keys[algorithm].privateKeyPem);
    expect(await provider.verify(otherDigest, signature, keys[algorithm].publicKeyPem)).toBe(false);
  });

  it("rejects a digest with one bit flipped", async () => {
    const signature = await provider.sign(digest, keys[algorithm].privateKeyPem);
    const altered = Buffer.from(digest);
    altered[0] ^= 0x01;
    expect(await provider.verify(altered, signature, keys[algorithm].publicKeyPem)).toBe(false);
  });

  it("rejects a signature with one bit flipped", async () => {
    const signature = await provider.sign(digest, keys[algorithm].privateKeyPem);
    const altered = Buffer.from(signature);
    altered[altered.length - 1] ^= 0x01;
    expect(await provider.verify(digest, altered, keys[algorithm].publicKeyPem)).toBe(false);
  });

  it("rejects a truncated signature", async () => {
    const signature = await provider.sign(digest, keys[algorithm].privateKeyPem);
    const truncated = signature.subarray(0, signature.length - 2);
    expect(await provider.verify(digest, truncated, keys[algorithm].publicKeyPem)).toBe(false);
  });

  it("rejects the right signature against the wrong public key of the same algorithm", async () => {
    const signature = await provider.sign(digest, keys[algorithm].privateKeyPem);
    expect(await provider.verify(digest, signature, spare[algorithm].publicKeyPem)).toBe(false);
  });
});

describe("signature shape matches each algorithm's specification", () => {
  it("RSA-PSS 3072 produces exactly 384 bytes (modulus length)", async () => {
    const signature = await providerFor("RSA").sign(digest, keys.RSA.privateKeyPem);
    expect(signature.length).toBe(384);
    expect(providerFor("RSA").signatureByteLength).toBe(384);
  });

  it("Ed25519 produces exactly 64 bytes (RFC 8032)", async () => {
    const signature = await providerFor("ED25519").sign(digest, keys.ED25519.privateKeyPem);
    expect(signature.length).toBe(64);
    expect(providerFor("ED25519").signatureByteLength).toBe(64);
  });

  it("ECDSA P-256 produces a DER SEQUENCE of two INTEGERs, 70-72 bytes", async () => {
    const signature = await providerFor("ECDSA_P256").sign(digest, keys.ECDSA_P256.privateKeyPem);
    expect(signature[0]).toBe(0x30); // SEQUENCE
    expect(signature[1]).toBe(signature.length - 2); // declared length matches actual
    expect(signature[2]).toBe(0x02); // INTEGER r
    const rLength = signature[3];
    expect(signature[4 + rLength]).toBe(0x02); // INTEGER s
    expect(signature.length).toBeGreaterThanOrEqual(68);
    expect(signature.length).toBeLessThanOrEqual(72);
    expect(providerFor("ECDSA_P256").signatureByteLength).toBeNull();
  });
});

describe("randomised vs deterministic signing", () => {
  it("RSA-PSS is randomised: two signatures differ, both verify", async () => {
    const a = await providerFor("RSA").sign(digest, keys.RSA.privateKeyPem);
    const b = await providerFor("RSA").sign(digest, keys.RSA.privateKeyPem);
    expect(a.equals(b)).toBe(false);
    expect(await providerFor("RSA").verify(digest, a, keys.RSA.publicKeyPem)).toBe(true);
    expect(await providerFor("RSA").verify(digest, b, keys.RSA.publicKeyPem)).toBe(true);
  });

  it("ECDSA is randomised: two signatures differ, both verify", async () => {
    const provider = providerFor("ECDSA_P256");
    const a = await provider.sign(digest, keys.ECDSA_P256.privateKeyPem);
    const b = await provider.sign(digest, keys.ECDSA_P256.privateKeyPem);
    expect(a.equals(b)).toBe(false);
    expect(await provider.verify(digest, a, keys.ECDSA_P256.publicKeyPem)).toBe(true);
    expect(await provider.verify(digest, b, keys.ECDSA_P256.publicKeyPem)).toBe(true);
  });

  it("Ed25519 is deterministic: the same digest and key give the identical signature", async () => {
    const provider = providerFor("ED25519");
    const a = await provider.sign(digest, keys.ED25519.privateKeyPem);
    const b = await provider.sign(digest, keys.ED25519.privateKeyPem);
    expect(a.equals(b)).toBe(true);
  });
});

describe("cross-algorithm substitution", () => {
  it("a signature made under one algorithm never verifies under another", async () => {
    for (const signingAlgorithm of ALGORITHMS) {
      const signature = await orchestrator.sign({
        algorithm: signingAlgorithm,
        digest,
        privateKeyPem: keys[signingAlgorithm].privateKeyPem,
      });

      for (const verifyingAlgorithm of ALGORITHMS) {
        if (verifyingAlgorithm === signingAlgorithm) continue;

        // Either a clean false, or a thrown "that is not my kind of key" -- both are
        // correct refusals. The verification workflow (Phase 6) maps the throw to
        // SIGNATURE_INVALID rather than letting it surface as a 500.
        const outcome = await orchestrator
          .verify({
            algorithm: verifyingAlgorithm,
            digest,
            signature,
            publicKeyPem: keys[verifyingAlgorithm].publicKeyPem,
          })
          .catch(() => "threw" as const);

        expect(outcome).not.toBe(true);
      }
    }
  });
});
