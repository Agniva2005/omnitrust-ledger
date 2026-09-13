// ML-DSA-65 cross-checked against an independent implementation.
//
// The production provider runs ML-DSA in OpenSSL through node:crypto. @noble/post-quantum
// is a separate, audited, pure-JavaScript implementation of FIPS 204, installed as a dev
// dependency for exactly this purpose. Agreement between the two is the evidence here:
// key generation from the same 32-byte seed yields byte-identical public keys, each
// implementation verifies the other's signatures, and each rejects an altered message.
//
// The OpenSSL command-line tool supports ML-DSA only from version 3.5, so unlike the
// classical algorithms this one is not also checked with the CLI.
import { createPrivateKey } from "node:crypto";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { beforeAll, describe, expect, it } from "vitest";
import { orchestrator, providerFor, type KeyPairPem } from "@/lib/crypto/orchestrator";
import { pemBody, toPem } from "@/lib/crypto/pem";

const PUBLIC_KEY_BYTES = 1952;
const provider = providerFor("ML_DSA_65");
const message = Buffer.from("OmniTrust post-quantum cross-implementation check");

let keys: KeyPairPem;
let seed: Uint8Array;

beforeAll(async () => {
  keys = await provider.generateKeyPair();
  // Node exports ML-DSA private keys as JWK (kty "AKP"), where `priv` is the FIPS 204 seed.
  const jwk = createPrivateKey(keys.privateKeyPem).export({ format: "jwk" }) as unknown as {
    kty: string;
    alg: string;
    priv: string;
  };
  expect(jwk.kty).toBe("AKP");
  expect(jwk.alg).toBe("ML-DSA-65");
  seed = new Uint8Array(Buffer.from(jwk.priv, "base64url"));
});

function rawPublicKey(publicKeyPem: string): Uint8Array {
  return new Uint8Array(pemBody(publicKeyPem).subarray(-PUBLIC_KEY_BYTES));
}

function altered(bytes: Buffer, index = 0): Buffer {
  const copy = Buffer.from(bytes);
  copy[index] ^= 0x01;
  return copy;
}

describe("key generation agrees across implementations", () => {
  it("derives a byte-identical public key from the same 32-byte seed", () => {
    expect(seed.length).toBe(32);
    const noble = ml_dsa65.keygen(seed);
    expect(noble.publicKey.length).toBe(PUBLIC_KEY_BYTES);
    expect(Buffer.from(noble.publicKey).equals(Buffer.from(rawPublicKey(keys.publicKeyPem)))).toBe(true);
  });
});

describe("signatures verify across implementations", () => {
  it("@noble/post-quantum verifies what the OpenSSL-backed provider signs, and rejects an altered message", async () => {
    const signature = new Uint8Array(await provider.sign(message, keys.privateKeyPem));
    const publicKey = rawPublicKey(keys.publicKeyPem);

    expect(ml_dsa65.verify(signature, new Uint8Array(message), publicKey)).toBe(true);
    expect(ml_dsa65.verify(signature, new Uint8Array(altered(message)), publicKey)).toBe(false);
  });

  it("the provider verifies what @noble/post-quantum signs with a key from the same seed", async () => {
    const noble = ml_dsa65.keygen(seed);
    const signature = ml_dsa65.sign(new Uint8Array(message), noble.secretKey);
    expect(signature.length).toBe(3309);

    expect(await provider.verify(message, signature, keys.publicKeyPem)).toBe(true);
    expect(await provider.verify(altered(message, 1), signature, keys.publicKeyPem)).toBe(false);
  });

  it("the provider accepts a public key it never generated, once carried in SubjectPublicKeyInfo", async () => {
    const noble = ml_dsa65.keygen(new Uint8Array(32).fill(0x2a));
    const signature = ml_dsa65.sign(new Uint8Array(message), noble.secretKey);

    // Reuse the SubjectPublicKeyInfo header from a real OpenSSL key; only the raw key differs.
    const der = pemBody(keys.publicKeyPem);
    const header = der.subarray(0, der.length - PUBLIC_KEY_BYTES);
    const publicKeyPem = toPem("PUBLIC KEY", Buffer.concat([header, Buffer.from(noble.publicKey)]));

    expect(orchestrator.identifyPublicKey(publicKeyPem)).toBe("ML_DSA_65");
    expect(await provider.verify(message, signature, publicKeyPem)).toBe(true);
  });
});
