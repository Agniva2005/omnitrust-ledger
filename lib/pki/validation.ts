// PKI layer: certificate validation. Used on its own (signing, the certificates page) and
// as the certificate step of the verification workflow.
import type { Certificate } from "@prisma/client";
import * as x509 from "@peculiar/x509";
import { caCertificate, getRootCa } from "@/lib/pki/ca";
import { parseCertificate } from "@/lib/pki/certificates";

export type CertificateFailureReason =
  | "CERTIFICATE_EXPIRED"
  | "CERTIFICATE_NOT_YET_VALID"
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
  /** Where the evaluation instant falls relative to the certificate's validity period. */
  window: "BEFORE" | "WITHIN" | "AFTER" | null;
  checks: ValidationCheck[];
};

export type ValidateOptions = {
  /** Instant to evaluate validity at. Defaults to now. */
  at?: Date;
  /**
   * "check" (default) treats a currently revoked certificate as invalid, which is right for
   * deciding whether a certificate may be used now. The verification workflow passes "skip"
   * and evaluates revocation itself against the signed CRL and the signature's trusted time.
   */
  revocation?: "check" | "skip";
};

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Validates the chain (including the issuer's own CA profile and validity), the
 * end-entity profile, the validity period and, unless skipped, revocation status, in that
 * order. Every check is recorded even after one fails. A certificate that is both expired
 * and revoked reports CERTIFICATE_EXPIRED, because expiry is checked first; both appear in
 * `checks`.
 */
export async function validateCertificate(
  certificate: Certificate,
  options: ValidateOptions = {},
): Promise<CertificateValidation> {
  const at = options.at ?? new Date();
  const checks: ValidationCheck[] = [];
  let chainValid = true;

  const check = (step: string, passed: boolean, detail?: string): boolean => {
    checks.push({ step, passed, detail });
    if (!passed) chainValid = false;
    return passed;
  };

  const ca = await getRootCa();
  const root = caCertificate(ca);

  let parsed: x509.X509Certificate;
  try {
    parsed = parseCertificate(certificate.certPem);
  } catch (error) {
    checks.push({ step: "Certificate parses as X.509", passed: false, detail: message(error) });
    return { valid: false, reason: "CERTIFICATE_CHAIN_INVALID", window: null, checks };
  }
  checks.push({ step: "Certificate parses as X.509", passed: true, detail: parsed.subject });

  // --- The issuer: the local CA, acting as a CA, inside its own validity period ---
  const issuerMatches = parsed.issuer === root.subject;
  check(
    "Issuer matches the local root CA",
    issuerMatches,
    issuerMatches ? root.subject : `issuer was ${parsed.issuer}`,
  );

  const issuerConstraints = root.getExtension(x509.BasicConstraintsExtension);
  check(
    "Issuer is a CA (basicConstraints cA=TRUE)",
    issuerConstraints?.ca === true,
    issuerConstraints ? undefined : "issuer certificate has no basicConstraints extension",
  );

  check(
    "Issuer CA certificate within its validity period",
    at >= root.notBefore && at <= root.notAfter,
    `${root.notBefore.toISOString()} to ${root.notAfter.toISOString()}`,
  );

  let signatureByCa = false;
  try {
    signatureByCa = await parsed.verify({ publicKey: root.publicKey, signatureOnly: true });
  } catch (error) {
    check("CA signature check raised", false, message(error));
  }
  check(
    "Certificate signature verifies against the CA public key",
    signatureByCa,
    signatureByCa ? undefined : "signature does not verify under the root CA key",
  );

  // --- The end-entity profile: a document-signing certificate, not a CA ---
  const leafConstraints = parsed.getExtension(x509.BasicConstraintsExtension);
  check(
    "Certificate is an end-entity certificate (cA=FALSE)",
    leafConstraints?.ca !== true,
    leafConstraints?.ca ? "certificate is marked as a CA and must not sign documents" : undefined,
  );

  const keyUsage = parsed.getExtension(x509.KeyUsagesExtension);
  const permitsSigning =
    keyUsage !== null && (keyUsage.usages & x509.KeyUsageFlags.digitalSignature) !== 0;
  check(
    "Key usage permits digital signatures",
    permitsSigning,
    keyUsage
      ? permitsSigning
        ? undefined
        : "keyUsage does not include digitalSignature"
      : "certificate has no keyUsage extension",
  );

  // The stored metadata must agree with the certificate itself, otherwise the database
  // row could claim a validity window the certificate does not actually carry.
  const metadataAgrees =
    Math.abs(parsed.notAfter.getTime() - certificate.expiresAt.getTime()) < 1000 &&
    certificate.serialNumber.toUpperCase() === parsed.serialNumber.toUpperCase();
  check(
    "Stored metadata matches the certificate",
    metadataAgrees,
    metadataAgrees
      ? undefined
      : "database serial number or expiry does not match the certificate bytes",
  );

  let reason: CertificateFailureReason | undefined = chainValid
    ? undefined
    : "CERTIFICATE_CHAIN_INVALID";

  // --- Validity period ---
  const window = at < parsed.notBefore ? "BEFORE" : at > parsed.notAfter ? "AFTER" : "WITHIN";
  checks.push({
    step: "Within validity period",
    passed: window === "WITHIN",
    detail: `${parsed.notBefore.toISOString()} to ${parsed.notAfter.toISOString()}, evaluated at ${at.toISOString()}`,
  });
  // RFC 5280 path validation treats "not yet valid" and "expired" as different conditions.
  if (window !== "WITHIN" && !reason) reason = window === "BEFORE" ? "CERTIFICATE_NOT_YET_VALID" : "CERTIFICATE_EXPIRED";

  // --- Revocation, as currently recorded ---
  if (options.revocation !== "skip") {
    const revoked = certificate.status === "REVOKED";
    checks.push({
      step: "Not revoked",
      passed: !revoked,
      detail: revoked
        ? [
            `revoked ${certificate.revokedAt?.toISOString() ?? "at an unrecorded time"}`,
            `reason ${certificate.revocationReason ?? "unspecified"}`,
            certificate.invalidityDate
              ? `invalid from ${certificate.invalidityDate.toISOString()}`
              : null,
            certificate.revocationComment,
          ]
            .filter(Boolean)
            .join(", ")
        : undefined,
    });
    if (revoked && !reason) reason = "CERTIFICATE_REVOKED";
  }

  return { valid: reason === undefined, reason, window, checks };
}
