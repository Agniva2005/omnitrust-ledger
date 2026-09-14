// X.509 key handling for the PKI layer.
//
// Lives in lib/crypto because WebCrypto key import and SubjectPublicKeyInfo handling are
// cryptographic concerns the boundary rule keeps out of other layers. The PKI layer calls
// these functions with an algorithm identifier and never names an algorithm itself.
//
// `Algorithm` in this file is the global WebCrypto type; ours is SignatureAlgorithm.
import { webcrypto } from "node:crypto";
// @peculiar/x509 loads the reflect-metadata polyfill that tsyringe needs, so it is imported first.
import * as x509 from "@peculiar/x509";
import { container } from "tsyringe";
import { ALGORITHMS, providerFor, type Algorithm as SignatureAlgorithm } from "@/lib/crypto/orchestrator";
import { pemBody, toPem } from "@/lib/crypto/pem";
import type { CertificateSigningParams } from "@/lib/crypto/types";

type WebCryptoParams = Algorithm & { hash?: string; namedCurve?: string; saltLength?: number };

let configured = false;

/**
 * @peculiar/x509 translates between WebCrypto algorithm names and X.509 AlgorithmIdentifiers
 * through a dependency-injection registry that has no entry for algorithms newer than the library,
 * such as ML-DSA. Each issuer-capable provider that declares its OID gets a mapping here.
 *
 * The AlgorithmIdentifier class is taken from an object the library itself built:
 * @peculiar/asn1-x509 ships separate CommonJS and ES module builds, and an instance of the class
 * from the other build does not serialise inside the library.
 */
function registerAlgorithmIdentifiers() {
  const edAlgorithm = new x509.EdAlgorithm() as unknown as { toAsnAlgorithm(algorithm: { name: string }): object | null };
  const reference = edAlgorithm.toAsnAlgorithm({ name: "Ed25519" });
  if (!reference) throw new Error("@peculiar/x509 no longer maps Ed25519; cannot locate its AlgorithmIdentifier class");
  const AlgorithmIdentifier = reference.constructor as new (init: { algorithm: string }) => typeof reference;

  for (const algorithm of ALGORITHMS) {
    const signing = providerFor(algorithm).certificateSigning;
    const oid = signing?.algorithmIdentifierOid;
    if (!signing || !oid) continue;
    const name = signing.signing.name;
    container.register(x509.diAlgorithm, {
      useValue: {
        toAsnAlgorithm: (candidate: { name: string }) =>
          candidate.name.toUpperCase() === name.toUpperCase() ? new AlgorithmIdentifier({ algorithm: oid }) : null,
        toWebAlgorithm: (candidate: { algorithm: string }) => (candidate.algorithm === oid ? { name } : null),
      },
    });
  }
}

/** @peculiar/x509 needs a WebCrypto implementation; Node's is standards-compliant. */
export function configureCertificateProvider() {
  if (configured) return;
  x509.cryptoProvider.set(webcrypto as unknown as Crypto);
  registerAlgorithmIdentifiers();
  configured = true;
}

function issuerParams(algorithm: SignatureAlgorithm): CertificateSigningParams {
  const provider = providerFor(algorithm);
  if (!provider.certificateSigning) {
    throw new Error(
      `${provider.metadata.displayName} cannot act as a certificate issuer in this installation`,
    );
  }
  return provider.certificateSigning;
}

/** Parameters for an issuer's signature over a certificate's to-be-signed bytes. */
export function certificateSigningAlgorithm(algorithm: SignatureAlgorithm): WebCryptoParams {
  return issuerParams(algorithm).signing as WebCryptoParams;
}

export async function importIssuerPrivateKey(
  algorithm: SignatureAlgorithm,
  privateKeyPem: string,
): Promise<CryptoKey> {
  configureCertificateProvider();
  return webcrypto.subtle.importKey(
    "pkcs8",
    new Uint8Array(pemBody(privateKeyPem)),
    issuerParams(algorithm).keyImport as WebCryptoParams,
    false,
    ["sign"],
  );
}

export async function importIssuerPublicKey(
  algorithm: SignatureAlgorithm,
  publicKeyPem: string,
): Promise<CryptoKey> {
  configureCertificateProvider();
  return webcrypto.subtle.importKey(
    "spki",
    new Uint8Array(pemBody(publicKeyPem)),
    issuerParams(algorithm).keyImport as WebCryptoParams,
    true,
    ["verify"],
  );
}

/**
 * A certificate subject's public key, carried as its SubjectPublicKeyInfo bytes. This
 * needs no algorithm-specific import parameters, so any registered algorithm can be
 * certified, including ones WebCrypto cannot import.
 */
export function subjectPublicKey(publicKeyPem: string): x509.PublicKey {
  configureCertificateProvider();
  return new x509.PublicKey(new Uint8Array(pemBody(publicKeyPem)));
}

/** Re-encodes a SubjectPublicKeyInfo DER blob (as carried in a certificate) as PEM. */
export function spkiDerToPem(der: ArrayBuffer | Uint8Array): string {
  return toPem("PUBLIC KEY", der);
}
