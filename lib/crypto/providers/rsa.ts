import {
  constants,
  generateKeyPair as generateKeyPairCb,
  sign as signSync,
  verify as verifySync,
  type RSAKeyPairOptions,
} from "node:crypto";
import { promisify } from "node:util";
import type { KeyPairPem, SignatureProvider } from "@/lib/crypto/types";

const generateRsaKeyPair = promisify(generateKeyPairCb) as (
  type: "rsa",
  options: RSAKeyPairOptions<"pem", "pem">,
) => Promise<{ publicKey: string; privateKey: string }>;

const MODULUS_BITS = 3072;

const PSS_OPTIONS = {
  padding: constants.RSA_PKCS1_PSS_PADDING,
  saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
} as const;

export const rsaProvider: SignatureProvider = {
  algorithm: "RSA",
  displayName: `RSA-PSS ${MODULUS_BITS}`,
  description:
    `RSASSA-PSS, ${MODULUS_BITS}-bit modulus, SHA-256 with a digest-length salt (MGF1/SHA-256). ` +
    "Randomised: signing the same digest twice yields two different signatures, both valid.",
  signatureByteLength: MODULUS_BITS / 8,

  webCrypto: {
    keyImport: {
      name: "RSA-PSS",
      hash: "SHA-256",
      modulusLength: MODULUS_BITS,
      publicExponent: new Uint8Array([1, 0, 1]),
    },
    signing: { name: "RSA-PSS", hash: "SHA-256", saltLength: 32 },
  },

  async generateKeyPair(): Promise<KeyPairPem> {
    const { publicKey, privateKey } = await generateRsaKeyPair("rsa", {
      modulusLength: MODULUS_BITS,
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    return { publicKeyPem: publicKey, privateKeyPem: privateKey };
  },

  async sign(digest, privateKeyPem) {
    return signSync("sha256", digest, { key: privateKeyPem, ...PSS_OPTIONS });
  },

  async verify(digest, signature, publicKeyPem) {
    return verifySync("sha256", digest, { key: publicKeyPem, ...PSS_OPTIONS }, signature);
  },
};
