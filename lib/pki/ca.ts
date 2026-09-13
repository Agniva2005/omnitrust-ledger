// PKI layer: the local root Certificate Authority.
//
// Demo-grade by design: this CA is self-signed, lives in the same SQLite database as
// everything else, and its private key is encrypted with a key held in a local file.
// No external party trusts it. Stated in the UI footer and README.
import type { CertificateAuthority } from "@prisma/client";
import * as x509 from "@peculiar/x509";
import { NotFoundError } from "@/lib/api";
import { appendAuditEntry } from "@/lib/audit/log";
import {
  certificateSigningAlgorithm,
  configureCertificateProvider,
  importIssuerPrivateKey,
  importIssuerPublicKey,
} from "@/lib/crypto/keys";
import { assertAlgorithm, orchestrator } from "@/lib/crypto/orchestrator";
import { decryptString, encryptString } from "@/lib/crypto/symmetric";
import { prisma } from "@/lib/db";
import { CA_ALGORITHM } from "@/lib/pki/policy";

export const CA_SUBJECT =
  "CN=OmniTrust Demo Root CA,O=OmniTrust Ledger,OU=Demo PKI - Not For Production Use";

const CA_VALIDITY_YEARS = 10;

/** Creates the root CA if it does not exist yet. Idempotent: safe to re-run. */
export async function ensureRootCa(): Promise<CertificateAuthority> {
  const existing = await prisma.certificateAuthority.findFirst();
  if (existing) return existing;

  configureCertificateProvider();

  const keys = await orchestrator.generateKeyPair(CA_ALGORITHM);
  const privateKey = await importIssuerPrivateKey(CA_ALGORITHM, keys.privateKeyPem);
  const publicKey = await importIssuerPublicKey(CA_ALGORITHM, keys.publicKeyPem);

  const notBefore = new Date();
  const notAfter = new Date(notBefore);
  notAfter.setFullYear(notAfter.getFullYear() + CA_VALIDITY_YEARS);

  const certificate = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: "01",
    name: CA_SUBJECT,
    notBefore,
    notAfter,
    keys: { privateKey, publicKey },
    signingAlgorithm: certificateSigningAlgorithm(CA_ALGORITHM),
    extensions: [
      new x509.BasicConstraintsExtension(true, 1, true),
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign,
        true,
      ),
    ],
  });

  const ca = await prisma.certificateAuthority.create({
    data: {
      name: CA_SUBJECT,
      algorithm: CA_ALGORITHM,
      certPem: certificate.toString("pem"),
      encryptedPrivateKey: encryptString(keys.privateKeyPem),
    },
  });

  await appendAuditEntry({
    action: "CA_CREATED",
    targetType: "CertificateAuthority",
    targetId: ca.id,
    metadata: { algorithm: CA_ALGORITHM, subject: CA_SUBJECT, notAfter: notAfter.toISOString() },
  });
  return ca;
}

export async function getRootCa(): Promise<CertificateAuthority> {
  const ca = await prisma.certificateAuthority.findFirst();
  if (!ca) throw new NotFoundError("No root CA has been created yet. Run `npm run setup`.");
  return ca;
}

export function caCertificate(ca: CertificateAuthority): x509.X509Certificate {
  configureCertificateProvider();
  return new x509.X509Certificate(ca.certPem);
}

/** Decrypts the CA private key and imports it for signing. Never returns the PEM. */
export async function caSigningKey(ca: CertificateAuthority): Promise<CryptoKey> {
  return importIssuerPrivateKey(
    assertAlgorithm(ca.algorithm),
    decryptString(ca.encryptedPrivateKey),
  );
}

export function caSigningAlgorithm(ca: CertificateAuthority) {
  return certificateSigningAlgorithm(assertAlgorithm(ca.algorithm));
}
