// Cryptographic Orchestration layer contract: types only.
//
// Everything above this layer (documents, PKI, API routes, UI) reaches algorithms
// through lib/crypto/orchestrator.ts and never names one. Algorithm-specific code lives
// only in lib/crypto/providers/; scripts/check-crypto-boundary.ts enforces that.

export type KeyPairPem = {
  /** SubjectPublicKeyInfo, PEM-encoded. */
  publicKeyPem: string;
  /** PKCS#8, PEM-encoded. Never persisted unencrypted. */
  privateKeyPem: string;
};

export type AlgorithmFamily = "RSA" | "ECDSA" | "EdDSA" | "ML-DSA";

export type SecurityClass = "classical" | "post-quantum";

/**
 * Declarative description of a provider. Every field is plain data so it can be sent to
 * the browser, and every numeric claim is checked against real key material and real
 * signatures by tests/crypto/metadata.test.ts.
 */
export type AlgorithmMetadata<Id extends string = string> = {
  /** Registry key, stored with certificates and signatures. */
  id: Id;
  displayName: string;
  family: AlgorithmFamily;
  securityClass: SecurityClass;
  description: string;
  standards: readonly string[];
  securityLevel: {
    /** Estimated classical security strength in bits, or null where a PQ category is the stated measure. */
    classicalBits: number | null;
    /** NIST post-quantum security category (1-5), or null for classical algorithms. */
    nistPqCategory: number | null;
    basis: string;
  };
  quantumResistance: string;
  implementation: {
    library: string;
    backend: string;
    version: string;
  };
  parameters: string;
  /** How the supplied message is processed before the signature primitive runs. */
  messageProcessing: string;
  deterministic: boolean;
  keySizes: {
    /** Length of the subjectPublicKey BIT STRING contents inside the SubjectPublicKeyInfo. */
    publicKeyBytes: number;
    publicKeyEncoding: string;
  };
  signature: {
    /** Exact length when the encoding is fixed, otherwise null. */
    fixedBytes: number | null;
    maxBytes: number;
    encoding: string;
  };
  serialization: {
    publicKey: string;
    privateKey: string;
  };
  oids: {
    publicKey: string;
    signature: string;
  };
  interoperability: {
    /**
     * An OpenSSL CLI command that independently verifies a signature produced by this
     * provider, with {publicKey}, {message} and {signature} standing for file paths. Null
     * when the OpenSSL CLI cannot do it. Exercised by tests/crypto/metadata.test.ts
     * whenever an `openssl` binary is available.
     */
    opensslVerify: string | null;
    note: string;
  };
  capabilities: {
    generateKeyPair: boolean;
    sign: boolean;
    verify: boolean;
    /** Keys of this algorithm can be certified in an X.509 certificate issued by this installation's CA. */
    x509Subject: boolean;
    /** This algorithm can sign X.509 certificates, i.e. act as a certificate authority here. */
    x509Issuer: boolean;
  };
  securityNotes: readonly string[];
};

/** WebCrypto parameters for signing certificates, for algorithms that can act as a CA. */
export type CertificateSigningParams = {
  keyImport: { name: string; namedCurve?: string; hash?: string };
  signing: { name: string; hash?: string; saltLength?: number };
};

export interface SignatureProvider<Id extends string = string> {
  readonly metadata: AlgorithmMetadata<Id>;

  /** Present exactly when metadata.capabilities.x509Issuer is true. */
  readonly certificateSigning: CertificateSigningParams | null;

  generateKeyPair(): Promise<KeyPairPem>;

  /**
   * Signs an arbitrary message. Any hashing is the algorithm's own and is described by
   * metadata.messageProcessing; callers never pre-hash on a provider's behalf.
   */
  sign(message: Uint8Array, privateKeyPem: string): Promise<Buffer>;

  /** Returns false for a signature that does not verify; throws only for an unusable key. */
  verify(message: Uint8Array, signature: Uint8Array, publicKeyPem: string): Promise<boolean>;

  /**
   * True when the key is of exactly this algorithm and parameter set (for example RSA with
   * this modulus size, or ECDSA on this curve). Never throws.
   */
  identifiesPublicKey(publicKeyPem: string): boolean;
}
