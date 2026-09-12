// WebCrypto key handling for the PKI layer.
//
// Lives in lib/crypto because node:crypto's webcrypto/subtle are cryptographic
// primitives and Section 2 rule 2 keeps those out of every other layer. The PKI
// layer calls these functions and never sees a raw algorithm name.
//
// `Algorithm` here is the global WebCrypto type; ours is aliased to SignatureAlgorithm.
import { webcrypto } from "node:crypto";
import * as x509 from "@peculiar/x509";
import { providerFor } from "@/lib/crypto/orchestrator";
import { toPem, type Algorithm as SignatureAlgorithm } from "@/lib/crypto/types";

type WebCryptoKeyParams = Algorithm & {
  hash?: string;
  namedCurve?: string;
  saltLength?: number;
  modulusLength?: number;
  publicExponent?: Uint8Array;
};

let configured = false;

/** @peculiar/x509 needs a WebCrypto implementation; Node's is standards-compliant. */
export function configureCertificateProvider() {
  if (configured) return;
  x509.cryptoProvider.set(webcrypto as unknown as Crypto);
  configured = true;
}

function importParams(algorithm: SignatureAlgorithm): WebCryptoKeyParams {
  return providerFor(algorithm).webCrypto.keyImport as WebCryptoKeyParams;
}

/** Signing algorithm parameters for the signature over a certificate's TBS bytes. */
export function certificateSigningAlgorithm(algorithm: SignatureAlgorithm): WebCryptoKeyParams {
  return providerFor(algorithm).webCrypto.signing as WebCryptoKeyParams;
}

export async function importPrivateKey(
  algorithm: SignatureAlgorithm,
  privateKeyPem: string,
): Promise<CryptoKey> {
  configureCertificateProvider();
  return webcrypto.subtle.importKey("pkcs8", pemDer(privateKeyPem), importParams(algorithm), false, [
    "sign",
  ]);
}

export async function importPublicKey(
  algorithm: SignatureAlgorithm,
  publicKeyPem: string,
): Promise<CryptoKey> {
  configureCertificateProvider();
  return webcrypto.subtle.importKey("spki", pemDer(publicKeyPem), importParams(algorithm), true, [
    "verify",
  ]);
}

function pemDer(pem: string): Uint8Array {
  const base64 = pem
    .split(/\r?\n/)
    .filter((line) => !line.startsWith("-----"))
    .join("");
  return new Uint8Array(Buffer.from(base64, "base64"));
}

/** Re-encodes a SubjectPublicKeyInfo DER blob (as carried in a certificate) as PEM. */
export function spkiDerToPem(der: ArrayBuffer | Uint8Array): string {
  return toPem("PUBLIC KEY", der instanceof Uint8Array ? der : new Uint8Array(der));
}
