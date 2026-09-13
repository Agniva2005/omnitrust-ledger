// A real ML-DSA-44 provider (FIPS 204) on OpenSSL, used only by tests/crypto/agility.test.ts.
//
// It is deliberately NOT in the production registry. Its job is to be an algorithm the
// rest of the codebase has never seen, so the agility test can show that document
// management, PKI and verification accept it without modification. It is not a stub: key
// generation, signing and verification are genuine ML-DSA operations.
import {
  createPublicKey,
  generateKeyPair as generateKeyPairCb,
  sign as signRaw,
  verify as verifyRaw,
} from "node:crypto";
import { promisify } from "node:util";
import type { KeyPairPem, SignatureProvider } from "@/lib/crypto/types";

// @types/node does not yet declare the ML-DSA key types that Node 24 with OpenSSL 3.5 supports.
const generateMlDsaKeyPair = promisify(generateKeyPairCb) as unknown as (
  type: string,
  options: {
    publicKeyEncoding: { type: "spki"; format: "pem" };
    privateKeyEncoding: { type: "pkcs8"; format: "pem" };
  },
) => Promise<{ publicKey: string; privateKey: string }>;

export const TEST_ALGORITHM_ID = "TEST_ML_DSA_44";

export const mlDsa44TestProvider = {
  metadata: {
    id: TEST_ALGORITHM_ID,
    displayName: "ML-DSA-44 (test-only provider)",
    family: "ML-DSA",
    securityClass: "post-quantum",
    description: "Module-lattice signature (FIPS 204) registered only inside the agility test.",
    standards: ["FIPS 204 (ML-DSA)"],
    securityLevel: {
      classicalBits: null,
      nistPqCategory: 2,
      basis: "FIPS 204 Table 1: ML-DSA-44 targets NIST security category 2",
    },
    quantumResistance: "Designed to resist known quantum attacks.",
    implementation: {
      library: "node:crypto",
      backend: "OpenSSL (native code)",
      version: `OpenSSL ${process.versions.openssl}`,
    },
    parameters: "ML-DSA-44, pure mode, empty context string",
    messageProcessing: "Pure ML-DSA over the supplied message",
    deterministic: false,
    keySizes: { publicKeyBytes: 1312, publicKeyEncoding: "FIPS 204 pkEncode, 1312 bytes" },
    signature: { fixedBytes: 2420, maxBytes: 2420, encoding: "FIPS 204 sigEncode, 2420 bytes" },
    serialization: { publicKey: "SubjectPublicKeyInfo, PEM", privateKey: "PKCS #8, PEM" },
    oids: { publicKey: "2.16.840.1.101.3.4.3.17", signature: "2.16.840.1.101.3.4.3.17" },
    interoperability: { opensslVerify: null, note: "Test-only provider." },
    capabilities: {
      generateKeyPair: true,
      sign: true,
      verify: true,
      x509Subject: true,
      x509Issuer: false,
    },
    securityNotes: ["Registered only inside tests/crypto/agility.test.ts."],
  },

  certificateSigning: null,

  async generateKeyPair(): Promise<KeyPairPem> {
    const { publicKey, privateKey } = await generateMlDsaKeyPair("ml-dsa-44", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    return { publicKeyPem: publicKey, privateKeyPem: privateKey };
  },

  async sign(message, privateKeyPem) {
    return signRaw(null, message, privateKeyPem);
  },

  async verify(message, signature, publicKeyPem) {
    return verifyRaw(null, message, publicKeyPem, signature);
  },

  identifiesPublicKey(publicKeyPem) {
    try {
      return (createPublicKey(publicKeyPem).asymmetricKeyType as string) === "ml-dsa-44";
    } catch {
      return false;
    }
  },
} satisfies SignatureProvider<typeof TEST_ALGORITHM_ID>;
