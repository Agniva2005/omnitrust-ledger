import { createPublicKey } from "node:crypto";
import * as ed25519 from "@noble/ed25519";
import noblePackage from "@noble/ed25519/package.json";
import { sha512 } from "@noble/hashes/sha512";
import { pemBody, toPem } from "@/lib/crypto/pem";
import type { KeyPairPem, SignatureProvider } from "@/lib/crypto/types";

// @noble/ed25519 v2 needs a SHA-512 supplied; @noble/hashes is the audited sibling
// package. Setting the sync hook enables both the sync and async APIs.
ed25519.etc.sha512Sync = (...messages) => sha512(ed25519.etc.concatBytes(...messages));

const SIGNATURE_BYTES = 64;
const RAW_KEY_BYTES = 32;

// RFC 8410 encodings. Ed25519 keys are fixed-length, so the DER wrapper around the
// raw key is a constant prefix -- this is serialisation, not cryptography. The tests
// confirm the result is byte-identical to what OpenSSL exports.
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

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

export const eddsaProvider = {
  metadata: {
    id: "ED25519",
    displayName: "EdDSA Ed25519",
    family: "EdDSA",
    securityClass: "classical",
    description:
      "Ed25519 (EdDSA over edwards25519, RFC 8032) via @noble/ed25519. Deterministic: the same " +
      "message and key always produce the same 64-byte signature.",
    standards: ["RFC 8032 (EdDSA)", "FIPS 186-5", "RFC 8410 (Ed25519 in X.509)"],
    securityLevel: {
      classicalBits: 128,
      nistPqCategory: null,
      basis: "RFC 8032 section 5.1: Ed25519 targets roughly 128 bits of security",
    },
    quantumResistance:
      "None. Shor's algorithm on a cryptographically relevant quantum computer recovers the private key.",
    implementation: {
      library: "@noble/ed25519",
      backend: "Pure JavaScript (audited)",
      version: `@noble/ed25519 ${noblePackage.version}`,
    },
    parameters: "edwards25519, SHA-512 internally, PureEdDSA (no pre-hash, no context)",
    messageProcessing: "PureEdDSA: the message is hashed with SHA-512 inside the signature algorithm (RFC 8032 section 5.1.6)",
    deterministic: true,
    keySizes: {
      publicKeyBytes: RAW_KEY_BYTES,
      publicKeyEncoding: "32-byte compressed Edwards point (RFC 8032 section 5.1.2)",
    },
    signature: {
      fixedBytes: SIGNATURE_BYTES,
      maxBytes: SIGNATURE_BYTES,
      encoding: "R || S, 64 bytes (RFC 8032 section 5.1.6)",
    },
    serialization: {
      publicKey: "SubjectPublicKeyInfo (RFC 8410), PEM",
      privateKey: "PKCS #8 with the 32-byte seed (RFC 8410), PEM",
    },
    oids: {
      publicKey: "1.3.101.112",
      signature: "1.3.101.112",
    },
    cms: {
      // RFC 8419: with signed attributes, the digest algorithm MUST be SHA-512.
      digestAlgorithmOid: "2.16.840.1.101.3.4.2.3",
      signatureAlgorithmOid: "1.3.101.112",
      signatureParametersDer: null,
      standard: "RFC 8419 (EdDSA in CMS)",
    },
    interoperability: {
      opensslVerify:
        "openssl pkeyutl -verify -pubin -inkey {publicKey} -rawin -in {message} -sigfile {signature}",
      // Neither the OpenSSL 3.2.4 nor the 3.4.0 CLI can create or verify Ed25519 CMS SignedData,
      // including signatures OpenSSL made itself ("no default digest" when signing, "Explicit
      // digest not allowed with EdDSA operations" when verifying).
      opensslCms: false,
      note: "OpenSSL 3.0 or later (-rawin).",
    },
    capabilities: {
      generateKeyPair: true,
      sign: true,
      verify: true,
      x509Subject: true,
      x509Issuer: true,
    },
    securityNotes: [
      "Deterministic signing removes the per-signature nonce that makes ECDSA fragile.",
      "Timings here are for a pure-JavaScript implementation and should not be read as a property of EdDSA itself.",
    ],
  },

  certificateSigning: {
    keyImport: { name: "Ed25519" },
    signing: { name: "Ed25519" },
  },

  async generateKeyPair(): Promise<KeyPairPem> {
    const seed = ed25519.utils.randomPrivateKey();
    const publicKey = await ed25519.getPublicKeyAsync(seed);
    return {
      publicKeyPem: toPem("PUBLIC KEY", Buffer.concat([SPKI_PREFIX, Buffer.from(publicKey)])),
      privateKeyPem: toPem("PRIVATE KEY", Buffer.concat([PKCS8_PREFIX, Buffer.from(seed)])),
    };
  },

  async sign(message, privateKeyPem) {
    return Buffer.from(await ed25519.signAsync(message, pkcs8PemToRaw(privateKeyPem)));
  },

  async verify(message, signature, publicKeyPem) {
    const publicKey = spkiPemToRaw(publicKeyPem);
    if (signature.length !== SIGNATURE_BYTES) return false;
    try {
      return await ed25519.verifyAsync(signature, message, publicKey);
    } catch {
      // noble throws on a structurally invalid signature (e.g. a non-canonical
      // scalar); that is an invalid signature, not an internal error.
      return false;
    }
  },

  identifiesPublicKey(publicKeyPem) {
    try {
      return createPublicKey(publicKeyPem).asymmetricKeyType === "ed25519";
    } catch {
      return false;
    }
  },
} satisfies SignatureProvider<"ED25519">;
