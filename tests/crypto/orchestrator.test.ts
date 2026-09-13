import { createHash, generateKeyPairSync } from "node:crypto";
import { beforeAll, describe, expect, it } from "vitest";
import {
  ALGORITHMS,
  assertAlgorithm,
  isAlgorithm,
  orchestrator,
  providerFor,
  type Algorithm,
} from "@/lib/crypto/orchestrator";
import { PROVIDERS, createRegistry } from "@/lib/crypto/registry";
import type { SignatureProvider } from "@/lib/crypto/types";

const message = createHash("sha256").update("resolve me by algorithm").digest();
const keys = {} as Record<Algorithm, { publicKeyPem: string; privateKeyPem: string }>;

beforeAll(async () => {
  for (const algorithm of ALGORITHMS) {
    keys[algorithm] = await orchestrator.generateKeyPair(algorithm);
  }
}, 60_000);

describe("algorithm parsing", () => {
  it("accepts exactly the registered algorithms", () => {
    expect([...ALGORITHMS].sort()).toEqual(Object.keys(PROVIDERS).sort());
    for (const algorithm of ALGORITHMS) expect(isAlgorithm(algorithm)).toBe(true);
    for (const bogus of ["rsa", "ECDSA", "ED448", "", null, "toString", "__proto__"]) {
      expect(isAlgorithm(bogus)).toBe(false);
    }
  });

  it("throws a named error for an unregistered algorithm", () => {
    expect(() => assertAlgorithm("DILITHIUM")).toThrow(/Unsupported algorithm: DILITHIUM/);
    expect(() => providerFor("DILITHIUM" as Algorithm)).toThrow();
  });
});

describe("registry integrity", () => {
  it("keys every provider by the identifier its own metadata declares", () => {
    for (const algorithm of ALGORITHMS) {
      expect(providerFor(algorithm).metadata.id).toBe(algorithm);
    }
  });

  it("refuses a provider registered under an identifier it does not declare", () => {
    const [first] = Object.values(PROVIDERS);
    expect(() => createRegistry({ WRONG_NAME: first as SignatureProvider })).toThrow(
      /registered as WRONG_NAME declares itself as/,
    );
  });

  it("refuses a provider whose issuer capability and certificate-signing parameters disagree", () => {
    const [id, provider] = Object.entries(PROVIDERS)[0];
    const inconsistent = { ...provider, certificateSigning: null } as SignatureProvider;
    expect(() => createRegistry({ [id]: inconsistent })).toThrow(/certificateSigning/);
  });

  it("refuses an empty registry", () => {
    expect(() => createRegistry({})).toThrow(/empty/);
  });
});

describe("routing", () => {
  it.each(ALGORITHMS)("signs and verifies %s through the orchestrator alone", async (algorithm) => {
    const signature = await orchestrator.sign({
      algorithm,
      message,
      privateKeyPem: keys[algorithm].privateKeyPem,
    });

    expect(
      await orchestrator.verify({
        algorithm,
        message,
        signature,
        publicKeyPem: keys[algorithm].publicKeyPem,
      }),
    ).toBe(true);
  });

  it("routes by the algorithm argument, not by inspecting the key", async () => {
    // Signing with one algorithm's key while claiming another must not silently succeed
    // by sniffing the PEM: the request's algorithm is authoritative.
    const [claimed, actual] = ALGORITHMS;
    await expect(
      orchestrator.sign({ algorithm: claimed, message, privateKeyPem: keys[actual].privateKeyPem }),
    ).rejects.toThrow();
  });

  it("refuses to sign for an unregistered algorithm", async () => {
    await expect(
      orchestrator.sign({
        algorithm: "FALCON" as Algorithm,
        message,
        privateKeyPem: keys[ALGORITHMS[0]].privateKeyPem,
      }),
    ).rejects.toThrow(/Unsupported algorithm/);
  });
});

describe("values read from storage", () => {
  it("looks up registered algorithms and returns null, never throws, for anything else", () => {
    for (const algorithm of ALGORITHMS) {
      expect(orchestrator.lookup(algorithm)?.id).toBe(algorithm);
    }
    expect(orchestrator.lookup("SOMETHING_REMOVED_LATER")).toBeNull();
  });

  it("gives an unsupported identifier a safe display label rather than crashing the page", () => {
    expect(orchestrator.displayName("SOMETHING_REMOVED_LATER")).toBe(
      "Unsupported algorithm (SOMETHING_REMOVED_LATER)",
    );
  });
});

describe("identifying a key from its material", () => {
  it.each(ALGORITHMS)("identifies a generated %s key as exactly that algorithm", (algorithm) => {
    expect(orchestrator.identifyPublicKey(keys[algorithm].publicKeyPem)).toBe(algorithm);
  });

  it("does not recognise the same key type with a different parameter set", () => {
    // A registered family is not enough: the parameter set must match the provider's.
    const pem = (key: ReturnType<typeof generateKeyPairSync>["publicKey"]) =>
      key.export({ type: "spki", format: "pem" }) as string;

    const rsa2048 = generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey;
    const p384 = generateKeyPairSync("ec", { namedCurve: "secp384r1" }).publicKey;
    const ed448 = generateKeyPairSync("ed448").publicKey;
    // Other ML-DSA parameter sets: @types/node does not yet declare these key types.
    const generateUntyped = generateKeyPairSync as unknown as (
      type: string,
    ) => { publicKey: import("node:crypto").KeyObject };
    const mlDsa44 = generateUntyped("ml-dsa-44").publicKey;
    const mlDsa87 = generateUntyped("ml-dsa-87").publicKey;

    for (const key of [rsa2048, p384, ed448, mlDsa44, mlDsa87]) {
      expect(orchestrator.identifyPublicKey(pem(key))).toBeNull();
    }
  });

  it("returns null for material that is not a public key at all", () => {
    expect(orchestrator.identifyPublicKey("not a key")).toBeNull();
    expect(orchestrator.identifyPublicKey(keys[ALGORITHMS[0]].privateKeyPem.replace(/PRIVATE/g, "PUBLIC"))).toBeNull();
  });
});
