import * as ed25519 from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { pemBody, toPem, type KeyPairPem, type SignatureProvider } from "@/lib/crypto/types";

// @noble/ed25519 v2 needs a SHA-512 supplied; @noble/hashes is the audited sibling
// package. Setting the sync hook enables both the sync and async APIs.
ed25519.etc.sha512Sync = (...messages) => sha512(ed25519.etc.concatBytes(...messages));

const SIGNATURE_BYTES = 64;
const RAW_KEY_BYTES = 32;

// RFC 8410 encodings. Ed25519 keys are fixed-length, so the DER wrapper around the
// raw key is a constant prefix -- this is serialisation, not cryptography. The tests
// confirm the result parses in OpenSSL (via node:crypto) and interoperates with it.
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function rawToPkcs8Pem(seed: Uint8Array): string {
  return toPem("PRIVATE KEY", Buffer.concat([PKCS8_PREFIX, Buffer.from(seed)]));
}

function rawToSpkiPem(publicKey: Uint8Array): string {
  return toPem("PUBLIC KEY", Buffer.concat([SPKI_PREFIX, Buffer.from(publicKey)]));
}

function pkcs8PemToRaw(pem: string): Buffer {
  const der = pemBody(pem);
  if (!der.subarray(0, PKCS8_PREFIX.length).equals(PKCS8_PREFIX)) {
    throw new Error("Not an Ed25519 PKCS#8 private key");
  }
  const seed = der.subarray(PKCS8_PREFIX.length);
  if (seed.length !== RAW_KEY_BYTES) throw new Error("Malformed Ed25519 private key");
  return seed;
}

function spkiPemToRaw(pem: string): Buffer {
  const der = pemBody(pem);
  if (!der.subarray(0, SPKI_PREFIX.length).equals(SPKI_PREFIX)) {
    throw new Error("Not an Ed25519 SubjectPublicKeyInfo");
  }
  const key = der.subarray(SPKI_PREFIX.length);
  if (key.length !== RAW_KEY_BYTES) throw new Error("Malformed Ed25519 public key");
  return key;
}

export const eddsaProvider: SignatureProvider = {
  algorithm: "ED25519",
  displayName: "EdDSA Ed25519",
  description:
    "Ed25519 (EdDSA over Curve25519, RFC 8032) via @noble/ed25519. Deterministic: the same " +
    "digest and key always produce the same 64-byte signature. Internally hashes with SHA-512.",
  signatureByteLength: SIGNATURE_BYTES,

  webCrypto: {
    keyImport: { name: "Ed25519" },
    signing: { name: "Ed25519" },
  },

  async generateKeyPair(): Promise<KeyPairPem> {
    const seed = ed25519.utils.randomPrivateKey();
    const publicKey = await ed25519.getPublicKeyAsync(seed);
    return { publicKeyPem: rawToSpkiPem(publicKey), privateKeyPem: rawToPkcs8Pem(seed) };
  },

  async sign(digest, privateKeyPem) {
    return Buffer.from(await ed25519.signAsync(digest, pkcs8PemToRaw(privateKeyPem)));
  },

  async verify(digest, signature, publicKeyPem) {
    const publicKey = spkiPemToRaw(publicKeyPem);
    if (signature.length !== SIGNATURE_BYTES) return false;
    try {
      return await ed25519.verifyAsync(signature, digest, publicKey);
    } catch {
      // noble throws on a structurally invalid signature (e.g. a non-canonical
      // scalar); that is an invalid signature, not an internal error.
      return false;
    }
  },
};

/** Exposed for the PKI layer, which needs the raw key bytes for X.509 encoding. */
export const ed25519Keys = { rawToSpkiPem, rawToPkcs8Pem, pkcs8PemToRaw, spkiPemToRaw };
