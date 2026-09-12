import {
  generateKeyPair as generateKeyPairCb,
  sign as signSync,
  verify as verifySync,
  type ECKeyPairOptions,
} from "node:crypto";
import { promisify } from "node:util";
import type { KeyPairPem, SignatureProvider } from "@/lib/crypto/types";

const generateEcKeyPair = promisify(generateKeyPairCb) as (
  type: "ec",
  options: ECKeyPairOptions<"pem", "pem">,
) => Promise<{ publicKey: string; privateKey: string }>;

// prime256v1 is OpenSSL's name for NIST P-256 / secp256r1.
const CURVE = "prime256v1";

export const ecdsaProvider: SignatureProvider = {
  algorithm: "ECDSA_P256",
  displayName: "ECDSA P-256",
  description:
    "ECDSA over NIST P-256 (secp256r1) with SHA-256, DER-encoded (SEQUENCE of two INTEGERs). " +
    "Randomised, and DER length varies with the leading bits of r and s.",
  // DER encoding is 70-72 bytes in practice; not fixed, so callers must not assume one.
  signatureByteLength: null,

  webCrypto: {
    keyImport: { name: "ECDSA", namedCurve: "P-256" },
    signing: { name: "ECDSA", hash: "SHA-256" },
  },

  async generateKeyPair(): Promise<KeyPairPem> {
    const { publicKey, privateKey } = await generateEcKeyPair("ec", {
      namedCurve: CURVE,
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    return { publicKeyPem: publicKey, privateKeyPem: privateKey };
  },

  async sign(digest, privateKeyPem) {
    return signSync("sha256", digest, { key: privateKeyPem, dsaEncoding: "der" });
  },

  async verify(digest, signature, publicKeyPem) {
    return verifySync("sha256", digest, { key: publicKeyPem, dsaEncoding: "der" }, signature);
  },
};
