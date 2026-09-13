// The verification workflow: report Figure 8, extended with trusted time.
//
// Steps run in a fixed order and each records its own status even after an earlier one
// fails, so the UI can show which check went wrong. The verdict keeps four outcomes
// distinct instead of collapsing "could not check" into "invalid":
//
//   VALID         every required step passed
//   INVALID       positive evidence that the content, signature, time-stamp or certificate is bad
//   UNVERIFIABLE  evidence needed for a decision could not be obtained
//   ERROR         the verifier itself failed, so its result supports no conclusion
//
// Time. A verified RFC 3161 time-stamp over the signature value proves the signature existed
// at its genTime. The certificate is then judged at that time, and revocation under the
// timestamp-aware policy in lib/pki/revocation.ts, so a certificate that later expires, or is
// later revoked for a reason that does not imply key compromise, does not retroactively
// invalidate a signature made while it was valid. Without a trusted time-stamp an expired or
// revoked certificate leaves the signature UNVERIFIABLE rather than INVALID, following the
// "no proof of existence" indications of ETSI EN 319 102-1.
import { NotFoundError, redactErrorForLog } from "@/lib/api";
import { appendAuditEntry } from "@/lib/audit/log";
import { requireCapability, type Actor } from "@/lib/auth/rbac";
import { sha256, sha256Hex } from "@/lib/crypto/hash";
import { isAlgorithm, orchestrator } from "@/lib/crypto/orchestrator";
import { DecryptionIntegrityError } from "@/lib/crypto/symmetric";
import { prisma } from "@/lib/db";
import { assertDocumentState, canTransition } from "@/lib/documents/lifecycle";
import { readBlob } from "@/lib/documents/storage";
import { HttpError } from "@/lib/errors";
import { publicKeyPemFromCertificate } from "@/lib/pki/certificates";
import { RevocationStatusUnavailableError, revocationStatus } from "@/lib/pki/crl";
import {
  REVOCATION_POLICY_ID,
  evaluateRevocation,
  type ProofOfExistence,
  type RevocationDecision,
} from "@/lib/pki/revocation";
import { verifyTimestampToken } from "@/lib/pki/tsa";
import { validateCertificate } from "@/lib/pki/validation";

export type VerificationOutcome = "VALID" | "INVALID" | "UNVERIFIABLE" | "ERROR";

/**
 * In precedence order. Certificate problems come first. An algorithm mismatch comes next:
 * a signature whose record, certificate and key disagree about the algorithm cannot be a
 * signature under that certificate at all. A hash mismatch outranks an invalid signature,
 * which outranks an invalid time-stamp: when the bytes change the signature fails too, and
 * when the signature changes its time-stamp no longer matches it, so the earlier finding
 * is the more precise diagnosis.
 */
export const INVALID_REASONS = [
  "CERTIFICATE_CHAIN_INVALID",
  "CERTIFICATE_EXPIRED",
  "CERTIFICATE_REVOKED",
  "ALGORITHM_MISMATCH",
  "HASH_MISMATCH",
  "SIGNATURE_INVALID",
  "TIMESTAMP_INVALID",
] as const;

export const ERROR_REASONS = ["INTERNAL_ERROR"] as const;

export const UNVERIFIABLE_REASONS = [
  "UNSUPPORTED_ALGORITHM",
  "CERTIFICATE_NOT_FOUND",
  "REVOCATION_STATUS_UNAVAILABLE",
  "REVOKED_NO_PROOF_OF_EXISTENCE",
  "EXPIRED_NO_PROOF_OF_EXISTENCE",
  "STORAGE_UNAVAILABLE",
] as const;

export type VerificationReason =
  | (typeof INVALID_REASONS)[number]
  | (typeof ERROR_REASONS)[number]
  | (typeof UNVERIFIABLE_REASONS)[number];

export type StepStatus = "PASS" | "FAIL" | "UNAVAILABLE" | "SKIPPED";

export type StepId =
  | "document"
  | "signature"
  | "certificate"
  | "timestamp"
  | "certificate-validity"
  | "revocation"
  | "public-key"
  | "recompute-hash"
  | "signature-verification"
  | "hash-comparison";

export type VerificationStep = {
  /** A StepId, or `certificate-validity:<n>` for the individual certificate checks. */
  id: string;
  step: string;
  status: StepStatus;
  /** True exactly when status is PASS. */
  passed: boolean;
  /** An optional step may be skipped or unavailable without preventing a VALID verdict. */
  optional?: boolean;
  detail?: string;
};

export type TrustSummary = {
  /** The server clock when the signature was stored. Not evidence. */
  claimedSigningTime: string;
  /** The verified time-stamp's genTime, or null without a trusted time-stamp. */
  trustedTime: string | null;
  timestampAccuracyMs: number | null;
  timestampAuthority: string | null;
  /** The instant the certificate's validity was judged at. */
  certificateEvaluatedAt: string | null;
  certificateExpiredSince: boolean;
  revocation: { reason: string; revokedAt: string; invalidityDate: string | null } | null;
  revocationDecision: RevocationDecision["code"] | null;
  policy: string;
};

export type VerificationResult = {
  outcome: VerificationOutcome;
  reason?: VerificationReason;
  /** Why, in a sentence or two. */
  explanation: string;
  trust: TrustSummary;
  steps: VerificationStep[];
};

/** Raised for a document that has no signature yet: neither valid nor invalid. */
export class DocumentNotSignedError extends HttpError {
  readonly status = 409;
  constructor(message = "This document has not been signed yet, so there is nothing to verify") {
    super(message);
    this.name = "DocumentNotSignedError";
  }
}

// Positive evidence of a bad document outranks a verifier fault, which outranks missing
// evidence: a revoked certificate is a sound finding even if the blob is unreadable, but
// an unreadable blob never proves anything about the document.
const REASON_PRECEDENCE: readonly VerificationReason[] = [
  ...INVALID_REASONS,
  ...ERROR_REASONS,
  ...UNVERIFIABLE_REASONS,
];

export function outcomeForReason(reason: VerificationReason): VerificationOutcome {
  if ((INVALID_REASONS as readonly string[]).includes(reason)) return "INVALID";
  if ((ERROR_REASONS as readonly string[]).includes(reason)) return "ERROR";
  return "UNVERIFIABLE";
}

/** Filesystem failures that mean "the bytes could not be read", not "the bytes are wrong". */
const STORAGE_UNAVAILABLE_CODES = new Set([
  "ENOENT",
  "EACCES",
  "EPERM",
  "EBUSY",
  "EIO",
  "EMFILE",
  "ENOTDIR",
  "EISDIR",
]);

function storageErrorCode(error: unknown): string | null {
  const code = (error as { code?: unknown } | null)?.code;
  return typeof code === "string" && STORAGE_UNAVAILABLE_CODES.has(code) ? code : null;
}

export type VerifyOptions = {
  /** The verification instant: when revocation status and, without a time-stamp, validity are judged. Defaults to now. */
  at?: Date;
  /** Verify a specific version instead of the latest. */
  versionNumber?: number;
};

const STEP: Record<StepId, string> = {
  document: "1. Retrieve document and recorded hash",
  signature: "2. Retrieve signature record",
  certificate: "3. Retrieve signing certificate",
  timestamp: "4. Verify trusted time-stamp (proof the signature existed)",
  "certificate-validity": "5. Validate certificate at the signing time: chain, profile, validity period",
  revocation: "6. Evaluate revocation from the CA's signed CRL",
  "public-key": "7. Extract public key from certificate and confirm its algorithm",
  "recompute-hash": "8. Recompute SHA-256 from the stored bytes",
  "signature-verification": "9. Verify signature against the recomputed hash",
  "hash-comparison": "10. Compare recomputed hash with the hash that was signed",
};

const REASON_SENTENCES: Record<VerificationReason, string> = {
  CERTIFICATE_CHAIN_INVALID:
    "The signing certificate does not chain to this installation's CA, lacks a document-signing profile, or disagrees with its stored record.",
  CERTIFICATE_EXPIRED: "The signature was made outside the signing certificate's validity period.",
  CERTIFICATE_REVOKED: "The signing certificate's revocation means this signature cannot be trusted.",
  ALGORITHM_MISMATCH:
    "The signature record, the certificate record and the certificate's key disagree about the algorithm.",
  HASH_MISMATCH: "The document content differs from the content that was signed.",
  SIGNATURE_INVALID: "The signature does not verify under the certificate's public key.",
  TIMESTAMP_INVALID: "The time-stamp attached to this signature is not a valid time-stamp for it.",
  INTERNAL_ERROR: "The verifier failed internally; the result supports no conclusion.",
  UNSUPPORTED_ALGORITHM: "This installation has no provider for the signature's algorithm.",
  CERTIFICATE_NOT_FOUND: "The certificate this signature refers to cannot be found.",
  REVOCATION_STATUS_UNAVAILABLE:
    "The CA's revocation list could not be obtained or authenticated, so revocation status is unknown.",
  REVOKED_NO_PROOF_OF_EXISTENCE:
    "The signing certificate has been revoked and there is no trusted time-stamp proving the signature existed before that.",
  EXPIRED_NO_PROOF_OF_EXISTENCE:
    "The signing certificate has expired and there is no trusted time-stamp proving the signature was made while it was valid.",
  STORAGE_UNAVAILABLE: "The stored document could not be read, so its content could not be checked.",
};

export async function verifyDocument(
  actor: Actor,
  documentId: string,
  options: VerifyOptions = {},
): Promise<VerificationResult> {
  requireCapability(actor, "document:verify");
  const now = options.at ?? new Date();

  const document = await prisma.document.findUnique({
    where: { id: documentId },
    include: { versions: { orderBy: { versionNumber: "desc" } } },
  });
  if (!document) throw new NotFoundError("Document not found");

  const version =
    options.versionNumber === undefined
      ? document.versions[0]
      : document.versions.find((candidate) => candidate.versionNumber === options.versionNumber);
  if (!version) throw new NotFoundError("Document version not found");

  const signature = await prisma.signature.findUnique({
    where: { documentVersionId: version.id },
  });
  if (!signature) throw new DocumentNotSignedError();

  const steps: VerificationStep[] = [];
  const reasons: VerificationReason[] = [];
  const record = (
    id: string,
    step: string,
    status: StepStatus,
    detail?: string,
    optional = false,
  ) => {
    steps.push({ id, step, status, passed: status === "PASS", detail, ...(optional ? { optional } : {}) });
  };

  const trust: TrustSummary = {
    claimedSigningTime: signature.signedAt.toISOString(),
    trustedTime: null,
    timestampAccuracyMs: null,
    timestampAuthority: null,
    certificateEvaluatedAt: null,
    certificateExpiredSince: false,
    revocation: null,
    revocationDecision: null,
    policy: REVOCATION_POLICY_ID,
  };
  let revocationDecision: RevocationDecision | null = null;

  record(
    "document",
    STEP.document,
    "PASS",
    `${document.filename} v${version.versionNumber}, recorded hash ${version.hash}`,
  );
  record(
    "signature",
    STEP.signature,
    "PASS",
    `${signature.algorithm}, ${signature.signatureBytes.length} bytes, stored ${signature.signedAt.toISOString()} (server clock)`,
  );

  let certificateSerial: string | null = null;

  try {
    // --- Step 3: the certificate used to sign ---
    const certificate = await prisma.certificate.findUnique({
      where: { id: signature.certificateId },
    });
    if (certificate) {
      certificateSerial = certificate.serialNumber;
      record(
        "certificate",
        STEP.certificate,
        "PASS",
        `serial ${certificate.serialNumber}, algorithm ${certificate.algorithm}`,
      );
    } else {
      record(
        "certificate",
        STEP.certificate,
        "UNAVAILABLE",
        "the certificate referenced by this signature cannot be found, so the signer cannot be established",
      );
      reasons.push("CERTIFICATE_NOT_FOUND");
    }

    // --- Step 4: the trusted time-stamp, as proof the signature existed ---
    let proof: ProofOfExistence | null = null;
    if (!signature.timestampToken) {
      record(
        "timestamp",
        STEP.timestamp,
        "SKIPPED",
        "no time-stamp was recorded; the signing time rests only on the server clock",
        true,
      );
    } else {
      const timestamp = await verifyTimestampToken(
        signature.timestampToken,
        sha256(signature.signatureBytes),
      );
      trust.timestampAuthority = timestamp.authority;
      if (timestamp.status === "VALID" && timestamp.genTime) {
        proof = { time: timestamp.genTime, accuracyMs: timestamp.accuracyMs };
        trust.trustedTime = timestamp.genTime.toISOString();
        trust.timestampAccuracyMs = timestamp.accuracyMs;
        record("timestamp", STEP.timestamp, "PASS", timestamp.explanation);
      } else if (timestamp.status === "INVALID") {
        record("timestamp", STEP.timestamp, "FAIL", timestamp.explanation);
        reasons.push("TIMESTAMP_INVALID");
      } else {
        record("timestamp", STEP.timestamp, "UNAVAILABLE", timestamp.explanation, true);
      }
    }

    // --- Step 5: the certificate, judged at the signing time when that time is proven ---
    if (certificate) {
      const evaluatedAt = proof?.time ?? now;
      trust.certificateEvaluatedAt = evaluatedAt.toISOString();
      trust.certificateExpiredSince = certificate.expiresAt < now;

      const validation = await validateCertificate(certificate, { at: evaluatedAt, revocation: "skip" });
      let status: StepStatus = validation.valid ? "PASS" : "FAIL";
      let detail = validation.valid
        ? proof
          ? `valid at the trusted signing time ${evaluatedAt.toISOString()}`
          : `valid now (${evaluatedAt.toISOString()}); no trusted signing time is available`
        : validation.reason;

      if (validation.reason === "CERTIFICATE_CHAIN_INVALID") {
        reasons.push("CERTIFICATE_CHAIN_INVALID");
      } else if (validation.reason === "CERTIFICATE_EXPIRED") {
        if (!proof && validation.window === "AFTER") {
          status = "UNAVAILABLE";
          detail = "the certificate has expired and no trusted time-stamp shows when the signature was made";
          reasons.push("EXPIRED_NO_PROOF_OF_EXISTENCE");
        } else {
          reasons.push("CERTIFICATE_EXPIRED");
        }
      }

      record("certificate-validity", STEP["certificate-validity"], status, detail);
      validation.checks.forEach((check, index) => {
        record(`certificate-validity:${index}`, check.step, check.passed ? "PASS" : "FAIL", check.detail);
      });
    } else {
      record("certificate-validity", STEP["certificate-validity"], "SKIPPED", "there is no certificate to validate");
    }

    // --- Step 6: revocation, from the CA's signed CRL, under the timestamp-aware policy ---
    if (certificate) {
      try {
        const status = await revocationStatus(certificate.serialNumber, now);
        revocationDecision = evaluateRevocation(status.revocation, proof);
        trust.revocationDecision = revocationDecision.code;
        trust.revocation = status.revocation
          ? {
              reason: status.revocation.reason,
              revokedAt: status.revocation.revokedAt.toISOString(),
              invalidityDate: status.revocation.invalidityDate?.toISOString() ?? null,
            }
          : null;

        const source = `CRL #${status.crlNumber ?? "?"} of ${status.crlThisUpdate.toISOString()}`;
        if (revocationDecision.verdict === "PASS") {
          record("revocation", STEP.revocation, "PASS", `${revocationDecision.explanation} (${source})`);
        } else if (revocationDecision.verdict === "INVALID") {
          record("revocation", STEP.revocation, "FAIL", `${revocationDecision.explanation} (${source})`);
          reasons.push("CERTIFICATE_REVOKED");
        } else {
          record("revocation", STEP.revocation, "UNAVAILABLE", `${revocationDecision.explanation} (${source})`);
          reasons.push("REVOKED_NO_PROOF_OF_EXISTENCE");
        }
      } catch (error) {
        if (!(error instanceof RevocationStatusUnavailableError)) throw error;
        record("revocation", STEP.revocation, "UNAVAILABLE", error.message);
        reasons.push("REVOCATION_STATUS_UNAVAILABLE");
      }
    } else {
      record("revocation", STEP.revocation, "SKIPPED", "there is no certificate to check");
    }

    // --- Step 7: extract the key from the certificate, and confirm what algorithm it is ---
    // The key material decides the algorithm. If the signature record, the certificate
    // record and the key itself disagree, no cryptographic operation is attempted: that is
    // how an algorithm-confusion or substitution attack would present.
    let publicKeyPem: string | null = null;
    if (certificate) {
      let extracted: string | null = null;
      try {
        extracted = publicKeyPemFromCertificate(certificate.certPem);
      } catch (error) {
        record("public-key", STEP["public-key"], "FAIL", error instanceof Error ? error.message : String(error));
        reasons.push("CERTIFICATE_CHAIN_INVALID");
      }

      if (extracted && !isAlgorithm(signature.algorithm)) {
        publicKeyPem = extracted;
        record(
          "public-key",
          STEP["public-key"],
          "PASS",
          "SubjectPublicKeyInfo extracted from the certificate; its algorithm cannot be compared with a signature algorithm this installation does not support",
        );
      } else if (extracted) {
        const keyAlgorithm = orchestrator.identifyPublicKey(extracted);
        if (keyAlgorithm === signature.algorithm && keyAlgorithm === certificate.algorithm) {
          publicKeyPem = extracted;
          record(
            "public-key",
            STEP["public-key"],
            "PASS",
            `the certificate carries a ${keyAlgorithm} key, matching both the signature and certificate records`,
          );
        } else {
          record(
            "public-key",
            STEP["public-key"],
            "FAIL",
            `the certificate carries ${
              keyAlgorithm ? `a ${keyAlgorithm} key` : "a key no registered provider recognises"
            }, the signature record says ${signature.algorithm} and the certificate record says ${
              certificate.algorithm
            }; no verification is attempted across algorithms`,
          );
          reasons.push("ALGORITHM_MISMATCH");
        }
      }
    } else {
      record("public-key", STEP["public-key"], "SKIPPED", "there is no certificate to take a key from");
    }

    // --- Step 8: recompute the hash from the bytes stored right now ---
    let recomputedHash: string | null = null;
    try {
      recomputedHash = sha256Hex(await readBlob(version.storagePath));
      record("recompute-hash", STEP["recompute-hash"], "PASS", recomputedHash);
    } catch (error) {
      const code = storageErrorCode(error);
      if (error instanceof DecryptionIntegrityError) {
        record(
          "recompute-hash",
          STEP["recompute-hash"],
          "FAIL",
          "the stored blob failed its AES-256-GCM integrity check: the bytes on disk are not the bytes that were written",
        );
        reasons.push("HASH_MISMATCH");
      } else if (code) {
        record(
          "recompute-hash",
          STEP["recompute-hash"],
          "UNAVAILABLE",
          `the stored bytes could not be read (${code}), so the content cannot be checked either way`,
        );
        reasons.push("STORAGE_UNAVAILABLE");
      } else {
        throw error;
      }
    }

    // --- Step 9: verify the signature, with the algorithm taken from the record ---
    if (!isAlgorithm(signature.algorithm)) {
      record(
        "signature-verification",
        STEP["signature-verification"],
        "UNAVAILABLE",
        `no provider is registered for algorithm "${signature.algorithm}" in this installation`,
      );
      reasons.push("UNSUPPORTED_ALGORITHM");
    } else if (publicKeyPem && recomputedHash) {
      let signatureValid = false;
      let detail = `algorithm ${signature.algorithm}, resolved from the signature record`;
      try {
        signatureValid = await orchestrator.verify({
          algorithm: signature.algorithm,
          message: Buffer.from(recomputedHash, "hex"),
          signature: signature.signatureBytes,
          publicKeyPem,
        });
      } catch (error) {
        const summary = error instanceof Error ? error.message.split(/\r?\n/, 1)[0] : String(error);
        detail = `${signature.algorithm} verification rejected the key or signature: ${summary}`;
      }
      record("signature-verification", STEP["signature-verification"], signatureValid ? "PASS" : "FAIL", detail);
      if (!signatureValid) reasons.push("SIGNATURE_INVALID");
    } else {
      record(
        "signature-verification",
        STEP["signature-verification"],
        "SKIPPED",
        "requires a public key whose algorithm matches the signature, and readable stored bytes",
      );
    }

    // --- Step 10: compare the recomputed hash with the hash that was signed ---
    if (recomputedHash === null) {
      record("hash-comparison", STEP["hash-comparison"], "SKIPPED", "no recomputed hash is available");
    } else if (recomputedHash === version.hash) {
      record("hash-comparison", STEP["hash-comparison"], "PASS", `both ${version.hash}`);
    } else {
      record(
        "hash-comparison",
        STEP["hash-comparison"],
        "FAIL",
        `signed ${version.hash}, recomputed ${recomputedHash}`,
      );
      reasons.push("HASH_MISMATCH");
    }
  } catch (error) {
    console.error("Verification failed internally", redactErrorForLog(error));
    record(
      "verifier-error",
      "Verifier error",
      "FAIL",
      `verification could not be completed (${
        error instanceof Error ? error.name : "unknown error"
      }); the result supports no conclusion`,
    );
    reasons.push("INTERNAL_ERROR");
  }

  let reason = REASON_PRECEDENCE.find((candidate) => reasons.includes(candidate));
  if (!reason && !steps.every((step) => step.status === "PASS" || step.optional)) {
    // A required step that did not pass without recording why is a verifier bug. Never call it VALID.
    reason = "INTERNAL_ERROR";
  }
  const outcome: VerificationOutcome = reason ? outcomeForReason(reason) : "VALID";
  const explanation = explain(outcome, reason, trust, revocationDecision, orchestrator.displayName(signature.algorithm));

  if (outcome === "VALID") {
    const current = assertDocumentState(document.status);
    if (canTransition(current, "VERIFIED")) {
      await prisma.document.update({ where: { id: document.id }, data: { status: "VERIFIED" } });
    }
  }

  await appendAuditEntry({
    actorUserId: actor.userId,
    action: "DOCUMENT_VERIFIED",
    targetType: "Document",
    targetId: document.id,
    metadata: {
      outcome,
      reason: reason ?? null,
      algorithm: signature.algorithm,
      certificateSerial,
      versionNumber: version.versionNumber,
      trustedTime: trust.trustedTime,
      revocationDecision: trust.revocationDecision,
      failedSteps: steps
        .filter((step) => step.status !== "PASS" && !step.optional)
        .map((step) => `${step.step} [${step.status}]`),
    },
  });

  return { outcome, reason, explanation, trust, steps };
}

function explain(
  outcome: VerificationOutcome,
  reason: VerificationReason | undefined,
  trust: TrustSummary,
  decision: RevocationDecision | null,
  algorithmName: string,
): string {
  if (outcome !== "VALID") {
    const revocationRelated = reason === "CERTIFICATE_REVOKED" || reason === "REVOKED_NO_PROOF_OF_EXISTENCE";
    return revocationRelated && decision ? decision.explanation : REASON_SENTENCES[reason!];
  }

  const parts = [`The document is unchanged and its ${algorithmName} signature verifies.`];
  if (trust.trustedTime) {
    parts.push(`A trusted time-stamp proves the signature existed at ${trust.trustedTime}.`);
  } else {
    parts.push("There is no trusted time-stamp, so the signing time rests on the server clock.");
  }
  if (trust.certificateExpiredSince && trust.trustedTime) {
    parts.push("The certificate has since expired; it was valid when the signature was made.");
  }
  if (decision && decision.code !== "NOT_REVOKED") parts.push(decision.explanation);
  return parts.join(" ");
}
