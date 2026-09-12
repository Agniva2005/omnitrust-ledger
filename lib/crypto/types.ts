// Cryptographic Orchestration layer contract.
//
// Everything above this layer (documents, PKI, API routes, UI) speaks only in terms
// of `Algorithm` and `SignatureProvider`. Nothing above this layer may import
// node:crypto signing primitives or @noble/*; scripts/check-crypto-boundary.ts
// enforces that, per CLAUDE.md Section 2 rule 2.

export const ALGORITHMS = ["RSA", "ECDSA_P256", "ED25519"] as const;

export type Algorithm = (typeof ALGORITHMS)[number];

export function isAlgorithm(value: unknown): value is Algorithm {
  return typeof value === "string" && (ALGORITHMS as readonly string[]).includes(value);
}

export function assertAlgorithm(value: unknown): Algorithm {
  if (!isAlgorithm(value)) throw new Error(`Unsupported algorithm: ${String(value)}`);
  return value;
}

export type KeyPairPem = {
  /** SubjectPublicKeyInfo, PEM-encoded. */
  publicKeyPem: string;
  /** PKCS#8, PEM-encoded. Never persisted unencrypted. */
  privateKeyPem: string;
};

/**
 * Parameters the PKI layer hands to @peculiar/x509 when it builds and signs a
 * certificate. Declared per provider so that lib/pki never names an algorithm.
 */
export type WebCryptoParams = {
  /** For importing/generating the subject key. */
  keyImport: { name: string; namedCurve?: string; hash?: string; publicExponent?: Uint8Array; modulusLength?: number };
  /** For the signature over the certificate TBS bytes. */
  signing: { name: string; hash?: string; saltLength?: number };
};

export interface SignatureProvider {
  readonly algorithm: Algorithm;
  /** Short label for the UI, e.g. "RSA-PSS 3072". */
  readonly displayName: string;
  /** Precise description of the construction, shown in the UI and benchmark table. */
  readonly description: string;
  /** Byte length of a signature, or null when the encoding makes it variable (ECDSA DER). */
  readonly signatureByteLength: number | null;
  readonly webCrypto: WebCryptoParams;

  generateKeyPair(): Promise<KeyPairPem>;

  /**
   * Signs a digest. Callers pass the SHA-256 of the document (Phase 5 signs "the
   * current document hash"), so the signed payload is 32 bytes, identical across
   * all three algorithms.
   */
  sign(digest: Uint8Array, privateKeyPem: string): Promise<Buffer>;

  /** Never throws on a bad signature: returns false. Throws only on malformed keys. */
  verify(digest: Uint8Array, signature: Uint8Array, publicKeyPem: string): Promise<boolean>;
}

export const PEM_PUBLIC_HEADER = "-----BEGIN PUBLIC KEY-----";
export const PEM_PRIVATE_HEADER = "-----BEGIN PRIVATE KEY-----";

export function pemBody(pem: string): Buffer {
  const base64 = pem
    .split(/\r?\n/)
    .filter((line) => !line.startsWith("-----"))
    .join("");
  return Buffer.from(base64, "base64");
}

export function toPem(label: "PUBLIC KEY" | "PRIVATE KEY", der: Uint8Array): string {
  const base64 = Buffer.from(der).toString("base64");
  const lines = base64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}
