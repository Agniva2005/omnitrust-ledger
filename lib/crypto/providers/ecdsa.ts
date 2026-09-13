import {
  createPrivateKey,
  createPublicKey,
  generateKeyPair as generateKeyPairCb,
  sign as signSync,
  verify as verifySync,
  type ECKeyPairOptions,
  type KeyObject,
} from "node:crypto";
import { promisify } from "node:util";
import type { KeyPairPem, SignatureProvider } from "@/lib/crypto/types";

const generateEcKeyPair = promisify(generateKeyPairCb) as (
  type: "ec",
  options: ECKeyPairOptions<"pem", "pem">,
) => Promise<{ publicKey: string; privateKey: string }>;

// prime256v1 is OpenSSL's name for NIST P-256 / secp256r1.
const CURVE = "prime256v1";

function isOwnKey(key: KeyObject): boolean {
  return key.asymmetricKeyType === "ec" && key.asymmetricKeyDetails?.namedCurve === CURVE;
}

// OpenSSL follows the type of the key it is given, so an RSA key passed here would
// produce, or accept, an RSA signature. Checking the key type is what keeps this provider
// ECDSA on P-256 and nothing else.
function ownPrivateKey(privateKeyPem: string): KeyObject {
  const key = createPrivateKey(privateKeyPem);
  if (!isOwnKey(key)) throw new Error("Not an ECDSA P-256 private key");
  return key;
}

function ownPublicKey(publicKeyPem: string): KeyObject {
  const key = createPublicKey(publicKeyPem);
  if (!isOwnKey(key)) throw new Error("Not an ECDSA P-256 public key");
  return key;
}

export const ecdsaProvider = {
  metadata: {
    id: "ECDSA_P256",
    displayName: "ECDSA P-256",
    family: "ECDSA",
    securityClass: "classical",
    description:
      "ECDSA over NIST P-256 (secp256r1) with SHA-256, DER-encoded. Randomised, and the DER " +
      "length varies with the leading bytes of r and s.",
    standards: ["FIPS 186-5 (ECDSA)", "NIST SP 800-186 (P-256)", "RFC 5480 (EC keys in X.509)"],
    securityLevel: {
      classicalBits: 128,
      nistPqCategory: null,
      basis: "NIST SP 800-57 Part 1 Rev. 5, Table 2: a 256-bit elliptic-curve group provides about 128 bits of security",
    },
    quantumResistance:
      "None. Shor's algorithm on a cryptographically relevant quantum computer recovers the private key.",
    implementation: {
      library: "node:crypto",
      backend: "OpenSSL (native code)",
      version: `OpenSSL ${process.versions.openssl}`,
    },
    parameters: "Curve P-256 (secp256r1), SHA-256",
    messageProcessing: "SHA-256 over the supplied message, then ECDSA over the 256-bit hash",
    deterministic: false,
    keySizes: {
      publicKeyBytes: 65,
      publicKeyEncoding: "Uncompressed curve point: 0x04 || X || Y",
    },
    signature: {
      fixedBytes: null,
      maxBytes: 72,
      encoding: "DER SEQUENCE { r INTEGER, s INTEGER } (RFC 3279); usually 70-72 bytes",
    },
    serialization: {
      publicKey: "SubjectPublicKeyInfo (RFC 5280), PEM",
      privateKey: "PKCS #8 (RFC 5208), PEM",
    },
    oids: {
      publicKey: "1.2.840.10045.2.1",
      signature: "1.2.840.10045.4.3.2",
    },
    cms: {
      digestAlgorithmOid: "2.16.840.1.101.3.4.2.1",
      signatureAlgorithmOid: "1.2.840.10045.4.3.2",
      signatureParametersDer: null,
      standard: "RFC 5753 / RFC 5754 (ECDSA with SHA-256 in CMS)",
    },
    interoperability: {
      opensslVerify: "openssl dgst -sha256 -verify {publicKey} -signature {signature} {message}",
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
      "Each signature needs a fresh, secret, uniformly random nonce; OpenSSL generates it. A repeated or biased nonce reveals the private key.",
      "Signatures are not unique: (r, s) and (r, n - s) both verify.",
    ],
  },

  certificateSigning: {
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

  async sign(message, privateKeyPem) {
    return signSync("sha256", message, { key: ownPrivateKey(privateKeyPem), dsaEncoding: "der" });
  },

  async verify(message, signature, publicKeyPem) {
    return verifySync(
      "sha256",
      message,
      { key: ownPublicKey(publicKeyPem), dsaEncoding: "der" },
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
} satisfies SignatureProvider<"ECDSA_P256">;
