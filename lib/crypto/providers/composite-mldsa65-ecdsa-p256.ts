// Composite ML-DSA: ML-DSA-65 and ECDSA P-256 as one signature algorithm.
//
// Implements id-MLDSA65-ECDSA-P256-SHA512 from draft-ietf-lamps-pq-composite-sigs-19, the
// PQ/T hybrid the IETF LAMPS working group sent for publication. Both component signatures are
// computed over the same message representative, and a composite signature is valid only when
// both verify, so it stays unforgeable while either ML-DSA or ECDSA remains unbroken.
//
//   M' = Prefix || Label || len(ctx) || ctx || SHA-512(M)
//   ML-DSA-65.Sign(mldsaSK, M', ctx = Label)      pure ML-DSA, hedged
//   ECDSA-P256.Sign(ecSK, M') with SHA-256        DER Ecdsa-Sig-Value
//   signature  = mldsaSig (3309) || ecdsaSig (DER)
//   public key = mldsaPK (1952) || uncompressed P-256 point (65)
//   private key = mldsaSeed (32) || ECPrivateKey without its publicKey field
//
// The application context ctx is always empty here: this provider serves document signing and
// CMS, and draft-ietf-lamps-cms-composite-sigs-05 fixes the CMS context to the empty string.
// Both components run in OpenSSL through node:crypto. tests/crypto/composite.test.ts checks
// the implementation against the draft's published test vectors and against @noble/post-quantum.
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPair as generateKeyPairCb,
  sign as signRaw,
  verify as verifyRaw,
  type KeyObject,
} from "node:crypto";
import { promisify } from "node:util";
import { pemBody, toPem } from "@/lib/crypto/pem";
import type { KeyPairPem, SignatureProvider } from "@/lib/crypto/types";

/** Composite OID for id-MLDSA65-ECDSA-P256-SHA512 (draft-ietf-lamps-pq-composite-sigs-19, Section 6). */
export const COMPOSITE_OID = "1.3.6.1.5.5.7.6.45";
const COMPOSITE_OID_DER = Buffer.from("06082b0601050507062d", "hex");

const PREFIX = Buffer.from("CompositeAlgorithmSignatures2025", "ascii");
const LABEL = Buffer.from("COMPSIG-MLDSA65-ECDSA-P256-SHA512", "ascii");

const MLDSA_PUBLIC_KEY_BYTES = 1952;
const MLDSA_SIGNATURE_BYTES = 3309;
const MLDSA_SEED_BYTES = 32;
const EC_POINT_BYTES = 65;
const ECDSA_MAX_DER_BYTES = 72;

// PKCS#8 prefix for an ML-DSA-65 private key in the seed-only form of RFC 9881
// (version 0, id-ml-dsa-65, privateKey OCTET STRING wrapping [0] IMPLICIT OCTET STRING of 32 bytes).
const MLDSA65_SEED_PKCS8_PREFIX = Buffer.from("3034020100300b060960864801650304031204228020", "hex");
// SubjectPublicKeyInfo prefix for a raw ML-DSA-65 public key (id-ml-dsa-65, BIT STRING of 1953 bytes).
const MLDSA65_SPKI_PREFIX = Buffer.from("308207b2300b0609608648016503040312038207a100", "hex");
// namedCurve [0] for P-256 (prime256v1), as it appears inside an ECPrivateKey.
const P256_PARAMETERS = Buffer.from("a00a06082a8648ce3d030107", "hex");

const generateMlDsa = promisify(generateKeyPairCb) as unknown as (type: string, options: object) => Promise<{ publicKey: KeyObject; privateKey: KeyObject }>;
const generateEc = promisify(generateKeyPairCb) as unknown as (type: "ec", options: { namedCurve: string }) => Promise<{ publicKey: KeyObject; privateKey: KeyObject }>;

// ---------------------------------------------------------------------------------------------
// Minimal DER: only the fixed shapes this algorithm uses, each checked exactly.
// ---------------------------------------------------------------------------------------------

function encodeLength(length: number): Buffer {
  if (length < 0x80) return Buffer.from([length]);
  const bytes: number[] = [];
  for (let value = length; value > 0; value >>= 8) bytes.unshift(value & 0xff);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function tlv(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), encodeLength(content.length), content]);
}

type Element = { tag: number; content: Buffer; end: number };

function readElement(der: Buffer, offset: number): Element {
  if (offset + 2 > der.length) throw new Error("truncated DER");
  const tag = der[offset];
  let length = der[offset + 1];
  let header = 2;
  if (length & 0x80) {
    const count = length & 0x7f;
    if (count === 0 || count > 3 || offset + 2 + count > der.length) throw new Error("unsupported DER length");
    length = 0;
    for (let index = 0; index < count; index += 1) length = length * 256 + der[offset + 2 + index];
    header = 2 + count;
  }
  const end = offset + header + length;
  if (end > der.length) throw new Error("truncated DER");
  return { tag, content: der.subarray(offset + header, end), end };
}

/** The elements of a SEQUENCE's content, requiring the SEQUENCE to fill `der` exactly. */
function sequenceElements(der: Buffer): Element[] {
  const outer = readElement(der, 0);
  if (outer.tag !== 0x30 || outer.end !== der.length) throw new Error("expected a single DER SEQUENCE");
  const elements: Element[] = [];
  for (let offset = 0; offset < outer.content.length; ) {
    const element = readElement(outer.content, offset);
    elements.push(element);
    offset = element.end;
  }
  return elements;
}

/** AlgorithmIdentifier of exactly the composite OID with absent parameters (draft Section 5). */
function isCompositeAlgorithmIdentifier(element: Element): boolean {
  return element.tag === 0x30 && element.content.equals(COMPOSITE_OID_DER);
}

// ---------------------------------------------------------------------------------------------
// Key serialisation (draft Sections 4 and 5)
// ---------------------------------------------------------------------------------------------

function compositeSpki(rawPublicKey: Buffer): Buffer {
  const bitString = tlv(0x03, Buffer.concat([Buffer.from([0x00]), rawPublicKey]));
  return tlv(0x30, Buffer.concat([tlv(0x30, COMPOSITE_OID_DER), bitString]));
}

function compositePkcs8(rawPrivateKey: Buffer): Buffer {
  return tlv(0x30, Buffer.concat([Buffer.from("020100", "hex"), tlv(0x30, COMPOSITE_OID_DER), tlv(0x04, rawPrivateKey)]));
}

/** The raw composite public key from its SubjectPublicKeyInfo, or a thrown refusal for any other key. */
function rawPublicKeyFromPem(publicKeyPem: string): Buffer {
  const [algorithm, subjectPublicKey, ...rest] = sequenceElements(pemBody(publicKeyPem));
  if (!algorithm || !isCompositeAlgorithmIdentifier(algorithm) || !subjectPublicKey || rest.length > 0) {
    throw new Error("Not an ML-DSA-65 + ECDSA P-256 composite public key");
  }
  if (subjectPublicKey.tag !== 0x03 || subjectPublicKey.content[0] !== 0x00) throw new Error("Malformed composite public key");
  const raw = subjectPublicKey.content.subarray(1);
  if (raw.length !== MLDSA_PUBLIC_KEY_BYTES + EC_POINT_BYTES || raw[MLDSA_PUBLIC_KEY_BYTES] !== 0x04) {
    throw new Error("Malformed composite public key");
  }
  return raw;
}

function rawPrivateKeyFromPem(privateKeyPem: string): Buffer {
  const [version, algorithm, privateKey, ...rest] = sequenceElements(pemBody(privateKeyPem));
  if (
    !version ||
    version.tag !== 0x02 ||
    !version.content.equals(Buffer.from([0x00])) ||
    !algorithm ||
    !isCompositeAlgorithmIdentifier(algorithm) ||
    !privateKey ||
    privateKey.tag !== 0x04
  ) {
    throw new Error("Not an ML-DSA-65 + ECDSA P-256 composite private key");
  }
  // Optional PKCS#8 attributes [0] are tolerated; nothing else may follow.
  if (rest.some((element) => element.tag !== 0xa0)) throw new Error("Malformed composite private key");
  return privateKey.content;
}

/** Component keys from the composite public key: ML-DSA-65 via its SPKI, ECDSA via the uncompressed point. */
function componentPublicKeys(raw: Buffer): { mldsa: KeyObject; ec: KeyObject } {
  const mldsa = createPublicKey({
    key: Buffer.concat([MLDSA65_SPKI_PREFIX, raw.subarray(0, MLDSA_PUBLIC_KEY_BYTES)]),
    format: "der",
    type: "spki",
  });
  const point = raw.subarray(MLDSA_PUBLIC_KEY_BYTES);
  const ec = createPublicKey({
    key: { kty: "EC", crv: "P-256", x: point.subarray(1, 33).toString("base64url"), y: point.subarray(33, 65).toString("base64url") },
    format: "jwk",
  });
  if ((mldsa.asymmetricKeyType as string) !== "ml-dsa-65" || ec.asymmetricKeyDetails?.namedCurve !== "prime256v1") {
    throw new Error("Composite public key components are not ML-DSA-65 and P-256");
  }
  return { mldsa, ec };
}

function componentPrivateKeys(raw: Buffer): { mldsa: KeyObject; ec: KeyObject } {
  if (raw.length <= MLDSA_SEED_BYTES) throw new Error("Malformed composite private key");
  const mldsa = createPrivateKey({
    key: Buffer.concat([MLDSA65_SEED_PKCS8_PREFIX, raw.subarray(0, MLDSA_SEED_BYTES)]),
    format: "der",
    type: "pkcs8",
  });
  const ec = createPrivateKey({ key: raw.subarray(MLDSA_SEED_BYTES), format: "der", type: "sec1" });
  if ((mldsa.asymmetricKeyType as string) !== "ml-dsa-65" || ec.asymmetricKeyDetails?.namedCurve !== "prime256v1") {
    throw new Error("Composite private key components are not ML-DSA-65 and P-256");
  }
  return { mldsa, ec };
}

/** ECPrivateKey (RFC 5915) with namedCurve and without the optional publicKey field, as the draft requires. */
function ecPrivateKeyWithoutPublicKey(ec: KeyObject): Buffer {
  const sec1 = ec.export({ format: "der", type: "sec1" });
  const [version, privateKey] = sequenceElements(sec1);
  if (version?.tag !== 0x02 || privateKey?.tag !== 0x04 || privateKey.content.length !== 32) {
    throw new Error("Unexpected ECPrivateKey encoding from OpenSSL");
  }
  return tlv(0x30, Buffer.concat([tlv(0x02, version.content), tlv(0x04, privateKey.content), P256_PARAMETERS]));
}

// ---------------------------------------------------------------------------------------------
// Message representative (draft Section 2.1)
// ---------------------------------------------------------------------------------------------

/** M' for the empty application context used by this installation. */
export function compositeMessageRepresentative(message: Uint8Array, context: Uint8Array = new Uint8Array(0)): Buffer {
  if (context.length > 255) throw new Error("Composite ML-DSA context must be at most 255 bytes");
  return Buffer.concat([PREFIX, LABEL, Buffer.from([context.length]), context, createHash("sha512").update(message).digest()]);
}

export const compositeMlDsa65EcdsaP256Provider = {
  metadata: {
    id: "MLDSA65_ECDSA_P256",
    displayName: "ML-DSA-65 + ECDSA P-256",
    family: "Composite",
    securityClass: "hybrid",
    description:
      "A PQ/T hybrid composite signature: ML-DSA-65 (FIPS 204) and ECDSA P-256 sign the same SHA-512 message " +
      "representative, and the result is valid only if both component signatures verify. It remains " +
      "unforgeable while either component is unbroken, at the cost of carrying both signatures and keys.",
    standards: [
      "draft-ietf-lamps-pq-composite-sigs-19 (id-MLDSA65-ECDSA-P256-SHA512)",
      "draft-ietf-lamps-cms-composite-sigs-05 (Composite ML-DSA in CMS)",
      "FIPS 204 (ML-DSA)",
      "FIPS 186-5 (ECDSA)",
    ],
    securityLevel: {
      classicalBits: 128,
      nistPqCategory: 3,
      basis:
        "Composite EUF-CMA security holds if either component is secure (draft-ietf-lamps-pq-composite-sigs-19, " +
        "Security Considerations): ML-DSA-65 is NIST post-quantum category 3 (FIPS 204, Table 1), and against " +
        "classical attackers the ECDSA P-256 component alone provides about 128 bits (NIST SP 800-57 Part 1 Rev. 5, Table 2)",
    },
    quantumResistance:
      "Resists quantum attack through the ML-DSA-65 component; the ECDSA component would fall to Shor's algorithm " +
      "but still protects against a classical break of ML-DSA or an implementation flaw in it.",
    implementation: {
      library: "node:crypto",
      backend: "OpenSSL (native code), composite encoding in this provider",
      version: `OpenSSL ${process.versions.openssl}`,
    },
    parameters: "ML-DSA-65 (pure, hedged, context = Label) + ECDSA P-256 with SHA-256; pre-hash SHA-512; empty application context",
    messageProcessing:
      "M' = \"CompositeAlgorithmSignatures2025\" || \"COMPSIG-MLDSA65-ECDSA-P256-SHA512\" || 0x00 || SHA-512(message); " +
      "both components sign M'",
    deterministic: false,
    keySizes: {
      publicKeyBytes: MLDSA_PUBLIC_KEY_BYTES + EC_POINT_BYTES,
      publicKeyEncoding: "ML-DSA-65 pkEncode (1952 bytes) || uncompressed P-256 point 0x04 || X || Y (65 bytes)",
    },
    signature: {
      fixedBytes: null,
      maxBytes: MLDSA_SIGNATURE_BYTES + ECDSA_MAX_DER_BYTES,
      encoding: "ML-DSA-65 sigEncode (3309 bytes) || DER Ecdsa-Sig-Value (RFC 3279, usually 70-72 bytes)",
    },
    serialization: {
      publicKey: "SubjectPublicKeyInfo with the composite OID and absent parameters, PEM",
      privateKey: "PKCS #8 with the composite OID: ML-DSA-65 seed (32 bytes) || ECPrivateKey without publicKey, PEM",
    },
    oids: {
      publicKey: COMPOSITE_OID,
      signature: COMPOSITE_OID,
    },
    cms: {
      // draft-ietf-lamps-cms-composite-sigs-05: the digest algorithm MUST be the composite's pre-hash, SHA-512.
      digestAlgorithmOid: "2.16.840.1.101.3.4.2.3",
      signatureAlgorithmOid: COMPOSITE_OID,
      signatureParametersDer: null,
      standard: "draft-ietf-lamps-cms-composite-sigs-05 (Composite ML-DSA in CMS)",
    },
    interoperability: {
      opensslVerify: null,
      opensslCms: false,
      note:
        "No released OpenSSL command-line tool implements composite ML-DSA. The implementation is checked against the " +
        "draft's published test vectors (signatures, keys and a self-signed certificate) and its ML-DSA component " +
        "against @noble/post-quantum, in tests/crypto/composite.test.ts.",
    },
    capabilities: {
      generateKeyPair: true,
      sign: true,
      verify: true,
      x509Subject: true,
      x509Issuer: false,
    },
    securityNotes: [
      "Specified by an Internet-Draft in the RFC Editor queue, not yet an RFC: identifiers or encodings may still change before publication.",
      "Largest keys and signatures of the registered algorithms: a 2017-byte public key and a signature of up to 3381 bytes.",
      "Both components must verify. A verifier that accepts either one alone would lose the hybrid guarantee, so verify never does.",
      "Cannot act as this installation's CA: certificate signing uses WebCrypto, which has no composite algorithms.",
    ],
  },

  certificateSigning: null,

  async generateKeyPair(): Promise<KeyPairPem> {
    const [mldsa, ec] = await Promise.all([generateMlDsa("ml-dsa-65", {}), generateEc("ec", { namedCurve: "prime256v1" })]);

    // Node exports an ML-DSA private key as JWK (kty "AKP") whose `priv` is the FIPS 204 seed.
    const jwk = mldsa.privateKey.export({ format: "jwk" }) as unknown as { kty?: string; priv?: string };
    const seed = Buffer.from(jwk.priv ?? "", "base64url");
    if (jwk.kty !== "AKP" || seed.length !== MLDSA_SEED_BYTES) throw new Error("Could not export the ML-DSA-65 seed");

    const mldsaSpki = mldsa.publicKey.export({ format: "der", type: "spki" });
    const ecJwk = ec.publicKey.export({ format: "jwk" });
    const point = Buffer.concat([Buffer.from([0x04]), Buffer.from(ecJwk.x!, "base64url"), Buffer.from(ecJwk.y!, "base64url")]);
    if (point.length !== EC_POINT_BYTES) throw new Error("Unexpected P-256 public key length");

    const rawPublicKey = Buffer.concat([mldsaSpki.subarray(mldsaSpki.length - MLDSA_PUBLIC_KEY_BYTES), point]);
    const rawPrivateKey = Buffer.concat([seed, ecPrivateKeyWithoutPublicKey(ec.privateKey)]);
    return {
      publicKeyPem: toPem("PUBLIC KEY", compositeSpki(rawPublicKey)),
      privateKeyPem: toPem("PRIVATE KEY", compositePkcs8(rawPrivateKey)),
    };
  },

  async sign(message, privateKeyPem) {
    const keys = componentPrivateKeys(rawPrivateKeyFromPem(privateKeyPem));
    const representative = compositeMessageRepresentative(message);
    const mldsaSignature = signRaw(null, representative, { key: keys.mldsa, context: LABEL } as never);
    const ecdsaSignature = signRaw("sha256", representative, { key: keys.ec, dsaEncoding: "der" });
    if (mldsaSignature.length !== MLDSA_SIGNATURE_BYTES) throw new Error("Unexpected ML-DSA-65 signature length");
    return Buffer.concat([mldsaSignature, ecdsaSignature]);
  },

  async verify(message, signature, publicKeyPem) {
    // A foreign or malformed key is refused by throwing, as every provider does.
    const keys = componentPublicKeys(rawPublicKeyFromPem(publicKeyPem));
    const bytes = Buffer.from(signature);
    if (bytes.length <= MLDSA_SIGNATURE_BYTES || bytes.length > MLDSA_SIGNATURE_BYTES + ECDSA_MAX_DER_BYTES) return false;
    const representative = compositeMessageRepresentative(message);
    try {
      const mldsaValid = verifyRaw(null, representative, { key: keys.mldsa, context: LABEL } as never, bytes.subarray(0, MLDSA_SIGNATURE_BYTES));
      // Both components are always evaluated; the composite is valid only if both are.
      const ecdsaValid = verifyRaw("sha256", representative, { key: keys.ec, dsaEncoding: "der" }, bytes.subarray(MLDSA_SIGNATURE_BYTES));
      return mldsaValid && ecdsaValid;
    } catch {
      // A structurally malformed component signature is an invalid signature, not an internal error.
      return false;
    }
  },

  identifiesPublicKey(publicKeyPem) {
    try {
      componentPublicKeys(rawPublicKeyFromPem(publicKeyPem));
      return true;
    } catch {
      return false;
    }
  },
} satisfies SignatureProvider<"MLDSA65_ECDSA_P256">;
