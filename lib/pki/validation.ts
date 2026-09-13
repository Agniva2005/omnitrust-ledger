// PKI layer: certificate validation. This is step 4 of the Figure 8 verification
// workflow, kept separate so it can be exercised on its own.
import type { Certificate } from "@prisma/client";
import { caCertificate, getRootCa } from "@/lib/pki/ca";
import { parseCertificate } from "@/lib/pki/certificates";

export type CertificateFailureReason =
  | "CERTIFICATE_EXPIRED"
  | "CERTIFICATE_REVOKED"
  | "CERTIFICATE_CHAIN_INVALID";

export type ValidationCheck = {
  step: string;
  passed: boolean;
  detail?: string;
};

export type CertificateValidation = {
  valid: boolean;
  reason?: CertificateFailureReason;
  checks: ValidationCheck[];
};

/**
 * Validates chain, validity period and revocation status, in the order CLAUDE.md
 * Section 3 step 4 lists them. A certificate that is both expired and revoked reports
 * CERTIFICATE_EXPIRED, because expiry is checked first; both appear in `checks`.
 */
export async function validateCertificate(
  certificate: Certificate,
  options: { at?: Date } = {},
): Promise<CertificateValidation> {
  const at = options.at ?? new Date();
  const checks: ValidationCheck[] = [];
  let reason: CertificateFailureReason | undefined;

  // --- Chain to the local root CA ---
  const ca = await getRootCa();
  const root = caCertificate(ca);
  let parsed;

  try {
    parsed = parseCertificate(certificate.certPem);
  } catch (error) {
    checks.push({
      step: "Certificate parses as X.509",
      passed: false,
      detail: error instanceof Error ? error.message : String(error),
    });
    return { valid: false, reason: "CERTIFICATE_CHAIN_INVALID", checks };
  }

  checks.push({ step: "Certificate parses as X.509", passed: true, detail: parsed.subject });

  const issuerMatches = parsed.issuer === root.subject;
  checks.push({
    step: "Issuer matches the local root CA",
    passed: issuerMatches,
    detail: issuerMatches ? root.subject : `issuer was ${parsed.issuer}`,
  });

  let signatureByCa = false;
  try {
    signatureByCa = await parsed.verify({ publicKey: root.publicKey, signatureOnly: true });
  } catch (error) {
    signatureByCa = false;
    checks.push({
      step: "CA signature check raised",
      passed: false,
      detail: error instanceof Error ? error.message : String(error),
    });
  }
  checks.push({
    step: "Certificate signature verifies against the CA public key",
    passed: signatureByCa,
    detail: signatureByCa ? undefined : "signature does not verify under the root CA key",
  });

  // The stored metadata must agree with the certificate itself, otherwise the database
  // row could claim a validity window the certificate does not actually carry.
  const metadataAgrees =
    Math.abs(parsed.notAfter.getTime() - certificate.expiresAt.getTime()) < 1000 &&
    certificate.serialNumber.toUpperCase() === parsed.serialNumber.toUpperCase();
  checks.push({
    step: "Stored metadata matches the certificate",
    passed: metadataAgrees,
    detail: metadataAgrees
      ? undefined
      : "database serial number or expiry does not match the certificate bytes",
  });

  if (!issuerMatches || !signatureByCa || !metadataAgrees) {
    reason = "CERTIFICATE_CHAIN_INVALID";
  }

  // --- Validity period ---
  const withinWindow = at >= parsed.notBefore && at <= parsed.notAfter;
  checks.push({
    step: "Within validity period",
    passed: withinWindow,
    detail: `${parsed.notBefore.toISOString()} to ${parsed.notAfter.toISOString()}`,
  });
  if (!withinWindow && !reason) reason = "CERTIFICATE_EXPIRED";

  // --- Revocation ---
  const revoked = certificate.status === "REVOKED";
  checks.push({
    step: "Not revoked",
    passed: !revoked,
    detail: revoked
      ? `revoked ${certificate.revokedAt?.toISOString() ?? "at an unrecorded time"}: ${
          certificate.revocationReason ?? "Unspecified"
        }`
      : undefined,
  });
  if (revoked && !reason) reason = "CERTIFICATE_REVOKED";

  return { valid: reason === undefined, reason, checks };
}
