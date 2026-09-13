import {
  createPrivateKey,
  createPublicKey,
  generateKeyPair as generateKeyPairCb,
  sign as signRaw,
  verify as verifyRaw,
  type KeyObject,
} from "node:crypto";
import { promisify } from "node:util";
import type { KeyPairPem, SignatureProvider } from "@/lib/crypto/types";

// OpenSSL's name for the ML-DSA-65 parameter set. Node 24 with OpenSSL 3.5 implements it;
// @types/node does not yet declare the ML-DSA key types, hence the casts below.
const KEY_TYPE = "ml-dsa-65";

const generateMlDsaKeyPair = promisify(generateKeyPairCb) as unknown as (
  type: string,
  options: {
    publicKeyEncoding: { type: "spki"; format: "pem" };
    privateKeyEncoding: { type: "pkcs8"; format: "pem" };
  },
) => Promise<{ publicKey: string; privateKey: string }>;

function isOwnKey(key: KeyObject): boolean {
  return (key.asymmetricKeyType as string) === KEY_TYPE;
}

// Refuse any key that is not ML-DSA-65, including the other ML-DSA parameter sets:
// OpenSSL would otherwise follow whatever key it is handed.
function ownPrivateKey(privateKeyPem: string): KeyObject {
  const key = createPrivateKey(privateKeyPem);
  if (!isOwnKey(key)) throw new Error("Not an ML-DSA-65 private key");
  return key;
}

function ownPublicKey(publicKeyPem: string): KeyObject {
  const key = createPublicKey(publicKeyPem);
  if (!isOwnKey(key)) throw new Error("Not an ML-DSA-65 public key");
  return key;
}

export const mlDsa65Provider = {
  metadata: {
    id: "ML_DSA_65",
    displayName: "ML-DSA-65",
    family: "ML-DSA",
    securityClass: "post-quantum",
    description:
      "Module-Lattice-Based Digital Signature Algorithm (FIPS 204) at parameter set ML-DSA-65, via " +
      "OpenSSL. Signing is hedged: each signature mixes in fresh randomness, so two signatures over " +
      "the same message differ and both verify.",
    standards: ["FIPS 204 (ML-DSA)", "RFC 9881 (ML-DSA in X.509)", "RFC 9882 (ML-DSA in CMS)"],
    securityLevel: {
      classicalBits: null,
      nistPqCategory: 3,
      basis: "FIPS 204, Table 1: ML-DSA-65 is claimed at NIST post-quantum security category 3",
    },
    quantumResistance:
      "Designed to resist attacks by quantum computers; its security rests on the Module-LWE and " +
      "Module-SIS lattice problems. It has a much shorter cryptanalytic history than RSA or elliptic curves.",
    implementation: {
      library: "node:crypto",
      backend: "OpenSSL (native code)",
      version: `OpenSSL ${process.versions.openssl}`,
    },
    parameters: "ML-DSA-65, pure mode (no pre-hash), empty context string, hedged signing",
    messageProcessing:
      "Pure ML-DSA: the message is absorbed with SHAKE256 inside the signature algorithm; no external pre-hash",
    deterministic: false,
    keySizes: {
      publicKeyBytes: 1952,
      publicKeyEncoding: "FIPS 204 pkEncode (rho || t1), carried directly in the SubjectPublicKeyInfo BIT STRING",
    },
    signature: {
      fixedBytes: 3309,
      maxBytes: 3309,
      encoding: "FIPS 204 sigEncode, 3309 bytes",
    },
    serialization: {
      publicKey: "SubjectPublicKeyInfo, PEM",
      privateKey: "PKCS #8 holding both the 32-byte seed and the expanded private key, as exported by OpenSSL, PEM",
    },
    oids: {
      publicKey: "2.16.840.1.101.3.4.3.18",
      signature: "2.16.840.1.101.3.4.3.18",
    },
    interoperability: {
      opensslVerify: null,
      note:
        "The OpenSSL command-line tool gained ML-DSA only in version 3.5, so no CLI command is declared. " +
        "Signatures are cross-verified against @noble/post-quantum, an independent FIPS 204 implementation, " +
        "in tests/crypto/mldsa-interop.test.ts.",
    },
    capabilities: {
      generateKeyPair: true,
      sign: true,
      verify: true,
      x509Subject: true,
      x509Issuer: false,
    },
    securityNotes: [
      "Public keys and signatures are far larger than the elliptic-curve alternatives: 1952 and 3309 bytes.",
      "Cannot act as this installation's CA: certificate signing uses WebCrypto, where Node marks ML-DSA as experimental.",
    ],
  },

  certificateSigning: null,

  async generateKeyPair(): Promise<KeyPairPem> {
    const { publicKey, privateKey } = await generateMlDsaKeyPair(KEY_TYPE, {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    return { publicKeyPem: publicKey, privateKeyPem: privateKey };
  },

  async sign(message, privateKeyPem) {
    return signRaw(null, message, ownPrivateKey(privateKeyPem));
  },

  async verify(message, signature, publicKeyPem) {
    const key = ownPublicKey(publicKeyPem);
    try {
      return verifyRaw(null, message, key, signature);
    } catch {
      // A structurally malformed signature is an invalid signature, not an internal error.
      return false;
    }
  },

  identifiesPublicKey(publicKeyPem) {
    try {
      return isOwnKey(createPublicKey(publicKeyPem));
    } catch {
      return false;
    }
  },
} satisfies SignatureProvider<"ML_DSA_65">;
