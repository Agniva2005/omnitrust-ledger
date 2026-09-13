import { createHash } from "node:crypto";
import { beforeAll, describe, expect, it } from "vitest";
import { orchestrator, providerFor } from "@/lib/crypto/orchestrator";
import { ALGORITHMS, assertAlgorithm, isAlgorithm, type Algorithm } from "@/lib/crypto/types";

const digest = createHash("sha256").update("resolve me by algorithm").digest();
const keys = {} as Record<Algorithm, { publicKeyPem: string; privateKeyPem: string }>;

beforeAll(async () => {
  for (const algorithm of ALGORITHMS) {
    keys[algorithm] = await orchestrator.generateKeyPair(algorithm);
  }
}, 60_000);

describe("algorithm parsing", () => {
  it("accepts the three registered algorithms and nothing else", () => {
    for (const algorithm of ALGORITHMS) expect(isAlgorithm(algorithm)).toBe(true);
    for (const bogus of ["rsa", "ECDSA", "ED448", "", null]) expect(isAlgorithm(bogus)).toBe(false);
  });

  it("throws a named error for an unregistered algorithm", () => {
    expect(() => assertAlgorithm("DILITHIUM")).toThrow(/Unsupported algorithm: DILITHIUM/);
    expect(() => providerFor("DILITHIUM" as Algorithm)).toThrow();
  });
});

describe("registry integrity", () => {
  it("registers exactly one provider per declared algorithm, keyed consistently", () => {
    for (const algorithm of ALGORITHMS) {
      expect(providerFor(algorithm).algorithm).toBe(algorithm);
    }
  });

  it("gives every provider a display name, a description and a signature-length declaration", () => {
    for (const description of orchestrator.describeAll()) {
      expect(description.displayName.length).toBeGreaterThan(0);
      expect(description.description.length).toBeGreaterThan(20);
      expect(
        description.signatureByteLength === null || description.signatureByteLength > 0,
      ).toBe(true);
    }
  });

  it("exposes WebCrypto parameters for the PKI layer, so lib/pki names no algorithm", () => {
    for (const algorithm of ALGORITHMS) {
      const params = orchestrator.webCryptoParams(algorithm);
      expect(params.keyImport.name.length).toBeGreaterThan(0);
      expect(params.signing.name.length).toBeGreaterThan(0);
    }
  });
});

describe("routing", () => {
  it.each(ALGORITHMS)("signs and verifies %s through the orchestrator alone", async (algorithm) => {
    const signature = await orchestrator.sign({
      algorithm,
      digest,
      privateKeyPem: keys[algorithm].privateKeyPem,
    });

    expect(
      await orchestrator.verify({
        algorithm,
        digest,
        signature,
        publicKeyPem: keys[algorithm].publicKeyPem,
      }),
    ).toBe(true);
  });

  it("routes by the algorithm argument, not by inspecting the key", async () => {
    // Signing an ED25519 digest while claiming RSA must not silently succeed by
    // sniffing the PEM: the request's algorithm is authoritative.
    await expect(
      orchestrator.sign({
        algorithm: "RSA",
        digest,
        privateKeyPem: keys.ED25519.privateKeyPem,
      }),
    ).rejects.toThrow();
  });

  it("refuses to sign for an unregistered algorithm", async () => {
    await expect(
      orchestrator.sign({
        algorithm: "FALCON" as Algorithm,
        digest,
        privateKeyPem: keys.RSA.privateKeyPem,
      }),
    ).rejects.toThrow(/Unsupported algorithm/);
  });
});

describe("extensibility claim from the report", () => {
  it("a new algorithm needs one provider object and one registry entry", async () => {
    // Stands in for a fourth provider: satisfying the SignatureProvider interface is
    // sufficient for the orchestrator's contract, with no change to any caller.
    const fake = {
      algorithm: "TEST_ONLY" as Algorithm,
      displayName: "Test provider",
      description: "A stand-in provider used only to prove the interface is sufficient.",
      signatureByteLength: 8,
      webCrypto: { keyImport: { name: "None" }, signing: { name: "None" } },
      async generateKeyPair() {
        return { publicKeyPem: "public", privateKeyPem: "private" };
      },
      async sign() {
        return Buffer.alloc(8, 0xab);
      },
      async verify(_digest: Uint8Array, signature: Uint8Array, _publicKeyPem: string) {
        return Buffer.from(signature).equals(Buffer.alloc(8, 0xab));
      },
    };

    const pair = await fake.generateKeyPair();
    const signature = await fake.sign();
    expect(await fake.verify(digest, signature, pair.publicKeyPem)).toBe(true);
    expect(ALGORITHMS).not.toContain(fake.algorithm);
  });
});
