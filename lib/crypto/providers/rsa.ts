import {
  constants,
  createPrivateKey,
  createPublicKey,
  generateKeyPair as generateKeyPairCb,
  sign as signSync,
  verify as verifySync,
  type KeyObject,
  type RSAKeyPairOptions,
} from "node:crypto";
import { promisify } from "node:util";
import type { KeyPairPem, SignatureProvider } from "@/lib/crypto/types";

const generateRsaKeyPair = promisify(generateKeyPairCb) as (
  type: "rsa",
  options: RSAKeyPairOptions<"pem", "pem">,
) => Promise<{ publicKey: string; privateKey: string }>;

const MODULUS_BITS = 3072;
const SALT_BYTES = 32;

const PSS_OPTIONS = {
  padding: constants.RSA_PKCS1_PSS_PADDING,
  saltLength: SALT_BYTES,
} as const;

function isOwnKey(key: KeyObject): boolean {
  return key.asymmetricKeyType === "rsa" && key.asymmetricKeyDetails?.modulusLength === MODULUS_BITS;
}

// OpenSSL follows the type of the key it is given and silently ignores the PSS options for
// a non-RSA key, so an ECDSA key passed here would produce, or accept, an ECDSA signature.
// Checking the key type is what keeps this provider RSA-PSS and nothing else.
function ownPrivateKey(privateKeyPem: string): KeyObject {
  const key = createPrivateKey(privateKeyPem);
  if (!isOwnKey(key)) throw new Error(`Not an RSA-${MODULUS_BITS} private key`);
  return key;
}

function ownPublicKey(publicKeyPem: string): KeyObject {
  const key = createPublicKey(publicKeyPem);
  if (!isOwnKey(key)) throw new Error(`Not an RSA-${MODULUS_BITS} public key`);
  return key;
}

export const rsaProvider = {
  metadata: {
    id: "RSA",
    displayName: `RSA-PSS ${MODULUS_BITS}`,
    family: "RSA",
    securityClass: "classical",
    description:
      `RSASSA-PSS with a ${MODULUS_BITS}-bit modulus, SHA-256, MGF1-SHA-256 and a ${SALT_BYTES}-byte salt. ` +
      "Randomised: signing the same message twice yields two different signatures, both valid.",
    standards: ["RFC 8017 (PKCS #1 v2.2, RSASSA-PSS)", "FIPS 186-5", "RFC 4055 (RSASSA-PSS in X.509)"],
    securityLevel: {
      classicalBits: 128,
      nistPqCategory: null,
      basis: "NIST SP 800-57 Part 1 Rev. 5, Table 2: a 3072-bit RSA modulus provides about 128 bits of security",
    },
    quantumResistance:
      "None. Shor's algorithm on a cryptographically relevant quantum computer recovers the private key.",
    implementation: {
      library: "node:crypto",
      backend: "OpenSSL (native code)",
      version: `OpenSSL ${process.versions.openssl}`,
    },
    parameters: `${MODULUS_BITS}-bit modulus, public exponent 65537, SHA-256, MGF1-SHA-256, ${SALT_BYTES}-byte salt`,
    messageProcessing: "SHA-256 over the supplied message, then EMSA-PSS encoding and the RSA private-key operation",
    deterministic: false,
    keySizes: {
      publicKeyBytes: 398,
      publicKeyEncoding: "RSAPublicKey DER: SEQUENCE { modulus INTEGER, publicExponent INTEGER }",
    },
    signature: {
      fixedBytes: MODULUS_BITS / 8,
      maxBytes: MODULUS_BITS / 8,
      encoding: "Big-endian integer the length of the modulus (RFC 8017 I2OSP)",
    },
    serialization: {
      publicKey: "SubjectPublicKeyInfo (RFC 5280), PEM",
      privateKey: "PKCS #8 (RFC 5208), PEM",
    },
    oids: {
      publicKey: "1.2.840.113549.1.1.1",
      signature: "1.2.840.113549.1.1.10",
    },
    cms: {
      digestAlgorithmOid: "2.16.840.1.101.3.4.2.1",
      signatureAlgorithmOid: "1.2.840.113549.1.1.10",
      // RSASSA-PSS-params: SHA-256, MGF1 with SHA-256, 32-byte salt. Byte-identical to the
      // parameters OpenSSL writes into its own RSA-PSS CMS signatures.
      signatureParametersDer:
        "3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a203020120",
      standard: "RFC 4056 (RSASSA-PSS in CMS)",
    },
    interoperability: {
      opensslVerify:
        "openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 -verify {publicKey} -signature {signature} {message}",
      opensslCms: true,
      note: "OpenSSL 1.1.1 or later.",
    },
    capabilities: {
      generateKeyPair: true,
      sign: true,
      verify: true,
      x509Subject: true,
      x509Issuer: true,
    },
    securityNotes: [
      "Key generation searches for large primes and is orders of magnitude slower than elliptic-curve key generation.",
      "Signatures and public keys are several times larger than the elliptic-curve alternatives at the same security level.",
    ],
  },

  certificateSigning: {
    keyImport: { name: "RSA-PSS", hash: "SHA-256" },
    signing: { name: "RSA-PSS", hash: "SHA-256", saltLength: SALT_BYTES },
  },

  async generateKeyPair(): Promise<KeyPairPem> {
    const { publicKey, privateKey } = await generateRsaKeyPair("rsa", {
      modulusLength: MODULUS_BITS,
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    return { publicKeyPem: publicKey, privateKeyPem: privateKey };
  },

  async sign(message, privateKeyPem) {
    return signSync("sha256", message, { key: ownPrivateKey(privateKeyPem), ...PSS_OPTIONS });
  },

  async verify(message, signature, publicKeyPem) {
    return verifySync(
      "sha256",
      message,
      { key: ownPublicKey(publicKeyPem), ...PSS_OPTIONS },
      signature,
    );
  },

  identifiesPublicKey(publicKeyPem) {
    try {
      return isOwnKey(createPublicKey(publicKeyPem));
    } catch {
      return false;
    }
  },
} satisfies SignatureProvider<"RSA">;
