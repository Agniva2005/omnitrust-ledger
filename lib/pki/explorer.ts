// PKI layer: everything the certificate explorer shows about one certificate, read from the
// certificate bytes, the CA, the signed CRL and the audit log. Nothing is derived from labels
// alone: fields come from the parsed X.509 structure, the key algorithm is identified from the
// key material, and revocation is read from the authenticated CRL.
import * as x509 from "@peculiar/x509";
import type { Actor } from "@/lib/auth/rbac";
import { sha256Hex } from "@/lib/crypto/hash";
import { orchestrator } from "@/lib/crypto/orchestrator";
import { pemBody } from "@/lib/crypto/pem";
import { prisma } from "@/lib/db";
import { caCertificate, getRootCa } from "@/lib/pki/ca";
import { getCertificate, parseCertificate, publicKeyPemFromCertificate } from "@/lib/pki/certificates";
import { RevocationStatusUnavailableError, revocationStatus } from "@/lib/pki/crl";
import { KEY_STATES, assertKeyState, nextKeyStates } from "@/lib/pki/keys";
import { validateCertificate } from "@/lib/pki/validation";

/** SHA-256 over the DER certificate, formatted as colon-separated uppercase hex. */
export function certificateFingerprint(certPem: string): string {
  return sha256Hex(pemBody(certPem)).toUpperCase().match(/.{2}/g)!.join(":");
}

function keyUsageNames(extension: x509.KeyUsagesExtension | null): string[] {
  if (!extension) return [];
  // A numeric TypeScript enum maps names to values and values back to names; keep only the
  // name -> non-zero flag entries.
  return (Object.entries(x509.KeyUsageFlags) as [string, string | number][])
    .map(([name, value]) => [name, Number(value)] as const)
    .filter(([name, flag]) => Number.isNaN(Number(name)) && flag !== 0 && (extension.usages & flag) !== 0)
    .map(([name]) => name);
}

export async function exploreCertificate(actor: Actor, certificateId: string) {
  const certificate = await getCertificate(actor, certificateId);
  const parsed = parseCertificate(certificate.certPem);
  const ca = await getRootCa();
  const root = caCertificate(ca);

  const keyAlgorithm = orchestrator.identifyPublicKey(publicKeyPemFromCertificate(certificate.certPem));
  const keyMetadata = keyAlgorithm ? orchestrator.describe(keyAlgorithm) : null;
  const basicConstraints = parsed.getExtension(x509.BasicConstraintsExtension);
  const keyUsage = parsed.getExtension(x509.KeyUsagesExtension);
  const extendedKeyUsage = parsed.getExtension(x509.ExtendedKeyUsageExtension);

  const validation = await validateCertificate(certificate);

  let revocation: {
    status: "NOT_REVOKED" | "REVOKED" | "UNAVAILABLE";
    crlNumber: number | null;
    reason: string | null;
    revokedAt: string | null;
    invalidityDate: string | null;
    detail: string;
  };
  try {
    const status = await revocationStatus(certificate.serialNumber);
    revocation = {
      status: status.revocation ? "REVOKED" : "NOT_REVOKED",
      crlNumber: status.crlNumber,
      reason: status.revocation?.reason ?? null,
      revokedAt: status.revocation?.revokedAt.toISOString() ?? null,
      invalidityDate: status.revocation?.invalidityDate?.toISOString() ?? null,
      detail: `from CRL #${status.crlNumber ?? "?"}, issued ${status.crlThisUpdate.toISOString()}, after checking its CA signature and freshness`,
    };
  } catch (error) {
    if (!(error instanceof RevocationStatusUnavailableError)) throw error;
    revocation = { status: "UNAVAILABLE", crlNumber: null, reason: null, revokedAt: null, invalidityDate: null, detail: error.message };
  }

  const [lifecycle, signatureCount, recentSignatures] = await Promise.all([
    prisma.auditLogEntry.findMany({
      where: {
        OR: [
          { targetType: "KeyPair", targetId: certificate.keyPair.id },
          { targetType: "Certificate", targetId: certificate.id },
        ],
      },
      orderBy: { seq: "asc" },
      include: { actor: { select: { email: true } } },
    }),
    prisma.signature.count({ where: { certificateId: certificate.id } }),
    prisma.signature.findMany({
      where: { certificateId: certificate.id },
      orderBy: { signedAt: "desc" },
      take: 10,
      include: { documentVersion: { select: { versionNumber: true, document: { select: { id: true, filename: true } } } } },
    }),
  ]);

  const keyState = assertKeyState(certificate.keyPair.status);

  return {
    id: certificate.id,
    status: certificate.status,
    algorithm: orchestrator.displayName(certificate.algorithm),
    subjectUser: certificate.subject.email,
    subject: parsed.subject,
    issuer: parsed.issuer,
    serialNumber: certificate.serialNumber,
    notBefore: parsed.notBefore.toISOString(),
    notAfter: parsed.notAfter.toISOString(),
    signedBy: orchestrator.displayName(ca.algorithm),
    publicKey: {
      algorithm: keyMetadata?.displayName ?? "not recognised by any registered provider",
      oid: keyMetadata?.oids.publicKey ?? null,
      bytes: keyMetadata?.keySizes.publicKeyBytes ?? null,
      securityClass: keyMetadata?.securityClass ?? null,
      matchesRecord: keyAlgorithm === certificate.algorithm,
    },
    extensions: {
      basicConstraints: basicConstraints ? { ca: basicConstraints.ca, critical: basicConstraints.critical } : null,
      keyUsage: keyUsage ? { names: keyUsageNames(keyUsage), critical: keyUsage.critical } : null,
      extendedKeyUsage: extendedKeyUsage ? extendedKeyUsage.usages.map(String) : [],
    },
    fingerprintSha256: certificateFingerprint(certificate.certPem),
    pem: certificate.certPem,
    chain: [
      {
        role: "Root CA (trust anchor)",
        subject: root.subject,
        issuer: root.issuer,
        selfSigned: root.subject === root.issuer,
        notBefore: root.notBefore.toISOString(),
        notAfter: root.notAfter.toISOString(),
        algorithm: orchestrator.displayName(ca.algorithm),
        fingerprintSha256: certificateFingerprint(ca.certPem),
      },
      {
        role: "End-entity (document signing)",
        subject: parsed.subject,
        issuer: parsed.issuer,
        selfSigned: false,
        notBefore: parsed.notBefore.toISOString(),
        notAfter: parsed.notAfter.toISOString(),
        algorithm: orchestrator.displayName(certificate.algorithm),
        fingerprintSha256: certificateFingerprint(certificate.certPem),
      },
    ],
    validation: { valid: validation.valid, reason: validation.reason ?? null, checks: validation.checks },
    revocation,
    key: {
      state: keyState,
      states: KEY_STATES,
      nextStates: nextKeyStates(keyState),
      rotatedAt: null as string | null,
    },
    lifecycle: lifecycle.map((entry) => ({
      seq: entry.seq,
      action: entry.action,
      at: entry.createdAt.toISOString(),
      by: entry.actor?.email ?? null,
      metadata: JSON.parse(entry.metadataJson) as Record<string, unknown>,
    })),
    signatures: {
      count: signatureCount,
      recent: recentSignatures.map((signature) => ({
        id: signature.id,
        documentId: signature.documentVersion.document.id,
        filename: signature.documentVersion.document.filename,
        versionNumber: signature.documentVersion.versionNumber,
        signedAt: signature.signedAt.toISOString(),
        timestamped: signature.timestampToken !== null,
      })),
    },
  };
}

export type CertificateExploration = Awaited<ReturnType<typeof exploreCertificate>>;
