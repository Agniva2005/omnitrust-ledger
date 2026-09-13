// The verification workflow, report Figure 8 / CLAUDE.md Section 3.
//
// Steps run in the spec's order and each records its own status even after an earlier
// one fails, so the UI can show which check went wrong. The verdict keeps four outcomes
// distinct instead of collapsing "could not check" into "invalid":
//
//   VALID         every step passed
//   INVALID       positive evidence that the content, signature or certificate is bad
//   UNVERIFIABLE  evidence needed for a decision could not be obtained
//   ERROR         the verifier itself failed, so its result supports no conclusion
import { NotFoundError, redactErrorForLog } from "@/lib/api";
import { appendAuditEntry } from "@/lib/audit/log";
import { requireCapability, type Actor } from "@/lib/auth/rbac";
import { sha256Hex } from "@/lib/crypto/hash";
import { isAlgorithm, orchestrator } from "@/lib/crypto/orchestrator";
import { DecryptionIntegrityError } from "@/lib/crypto/symmetric";
import { prisma } from "@/lib/db";
import { assertDocumentState, canTransition } from "@/lib/documents/lifecycle";
import { readBlob } from "@/lib/documents/storage";
import { HttpError } from "@/lib/errors";
import { publicKeyPemFromCertificate } from "@/lib/pki/certificates";
import { validateCertificate } from "@/lib/pki/validation";

export type VerificationOutcome = "VALID" | "INVALID" | "UNVERIFIABLE" | "ERROR";

/**
 * In precedence order. Certificate problems come first. An algorithm mismatch comes next:
 * a signature whose record, certificate and key disagree about the algorithm cannot be a
 * signature under that certificate at all. Then a hash mismatch outranks an invalid
 * signature: when the bytes have changed the signature necessarily fails too, and "the
 * document was altered" is the more precise diagnosis.
 */
export const INVALID_REASONS = [
  "CERTIFICATE_CHAIN_INVALID",
  "CERTIFICATE_EXPIRED",
  "CERTIFICATE_REVOKED",
  "ALGORITHM_MISMATCH",
  "HASH_MISMATCH",
  "SIGNATURE_INVALID",
] as const;

export const ERROR_REASONS = ["INTERNAL_ERROR"] as const;

export const UNVERIFIABLE_REASONS = [
  "UNSUPPORTED_ALGORITHM",
  "CERTIFICATE_NOT_FOUND",
  "STORAGE_UNAVAILABLE",
] as const;

export type VerificationReason =
  | (typeof INVALID_REASONS)[number]
  | (typeof ERROR_REASONS)[number]
  | (typeof UNVERIFIABLE_REASONS)[number];

export type StepStatus = "PASS" | "FAIL" | "UNAVAILABLE" | "SKIPPED";

export type VerificationStep = {
  step: string;
  status: StepStatus;
  /** True exactly when status is PASS. */
  passed: boolean;
  detail?: string;
};

export type VerificationResult = {
  outcome: VerificationOutcome;
  reason?: VerificationReason;
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
  /** Instant to evaluate certificate validity against. Defaults to now. */
  at?: Date;
  /** Verify a specific version instead of the latest. */
  versionNumber?: number;
};

const STEP = {
  document: "1. Retrieve document and recorded hash",
  signature: "2. Retrieve signature record",
  certificate: "3. Retrieve signing certificate",
  validation: "4. Validate certificate: chain to local CA, validity period, revocation",
  publicKey: "5. Extract public key from certificate and confirm its algorithm",
  recompute: "6. Recompute SHA-256 from the stored bytes",
  verify: "7. Verify signature against the recomputed hash",
  compare: "8. Compare recomputed hash with the hash that was signed",
} as const;

export async function verifyDocument(
  actor: Actor,
  documentId: string,
  options: VerifyOptions = {},
): Promise<VerificationResult> {
  requireCapability(actor, "document:verify");
  const at = options.at ?? new Date();

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
  const record = (step: string, status: StepStatus, detail?: string) => {
    steps.push({ step, status, passed: status === "PASS", detail });
  };

  record(
    STEP.document,
    "PASS",
    `${document.filename} v${version.versionNumber}, recorded hash ${version.hash}`,
  );
  record(
    STEP.signature,
    "PASS",
    `${signature.algorithm}, ${signature.signatureBytes.length} bytes, signed ${signature.signedAt.toISOString()}`,
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
        STEP.certificate,
        "PASS",
        `serial ${certificate.serialNumber}, algorithm ${certificate.algorithm}`,
      );
    } else {
      record(
        STEP.certificate,
        "UNAVAILABLE",
        "the certificate referenced by this signature cannot be found, so the signer cannot be established",
      );
      reasons.push("CERTIFICATE_NOT_FOUND");
    }

    // --- Step 4: validate the certificate ---
    if (certificate) {
      const validation = await validateCertificate(certificate, { at });
      record(
        STEP.validation,
        validation.valid ? "PASS" : "FAIL",
        validation.valid
          ? "chain, validity period and revocation status all pass"
          : validation.reason,
      );
      for (const check of validation.checks) {
        record(`4.${check.step}`, check.passed ? "PASS" : "FAIL", check.detail);
      }
      if (validation.reason) reasons.push(validation.reason);
    } else {
      record(STEP.validation, "SKIPPED", "there is no certificate to validate");
    }

    // --- Step 5: extract the key from the certificate, and confirm what algorithm it is ---
    // The key material decides the algorithm. If the signature record, the certificate
    // record and the key itself disagree, no cryptographic operation is attempted: that is
    // how an algorithm-confusion or substitution attack would present.
    let publicKeyPem: string | null = null;
    if (certificate) {
      let extracted: string | null = null;
      try {
        extracted = publicKeyPemFromCertificate(certificate.certPem);
      } catch (error) {
        record(STEP.publicKey, "FAIL", error instanceof Error ? error.message : String(error));
        reasons.push("CERTIFICATE_CHAIN_INVALID");
      }

      if (extracted && !isAlgorithm(signature.algorithm)) {
        publicKeyPem = extracted;
        record(
          STEP.publicKey,
          "PASS",
          "SubjectPublicKeyInfo extracted from the certificate; its algorithm cannot be compared with a signature algorithm this installation does not support",
        );
      } else if (extracted) {
        const keyAlgorithm = orchestrator.identifyPublicKey(extracted);
        if (keyAlgorithm === signature.algorithm && keyAlgorithm === certificate.algorithm) {
          publicKeyPem = extracted;
          record(
            STEP.publicKey,
            "PASS",
            `the certificate carries a ${keyAlgorithm} key, matching both the signature and certificate records`,
          );
        } else {
          record(
            STEP.publicKey,
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
      record(STEP.publicKey, "SKIPPED", "there is no certificate to take a key from");
    }

    // --- Step 6: recompute the hash from the bytes stored right now ---
    let recomputedHash: string | null = null;
    try {
      recomputedHash = sha256Hex(await readBlob(version.storagePath));
      record(STEP.recompute, "PASS", recomputedHash);
    } catch (error) {
      const code = storageErrorCode(error);
      if (error instanceof DecryptionIntegrityError) {
        record(
          STEP.recompute,
          "FAIL",
          "the stored blob failed its AES-256-GCM integrity check: the bytes on disk are not the bytes that were written",
        );
        reasons.push("HASH_MISMATCH");
      } else if (code) {
        record(
          STEP.recompute,
          "UNAVAILABLE",
          `the stored bytes could not be read (${code}), so the content cannot be checked either way`,
        );
        reasons.push("STORAGE_UNAVAILABLE");
      } else {
        throw error;
      }
    }

    // --- Step 7: verify the signature, with the algorithm taken from the record ---
    if (!isAlgorithm(signature.algorithm)) {
      record(
        STEP.verify,
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
      record(STEP.verify, signatureValid ? "PASS" : "FAIL", detail);
      if (!signatureValid) reasons.push("SIGNATURE_INVALID");
    } else {
      record(
        STEP.verify,
        "SKIPPED",
        "requires a public key whose algorithm matches the signature, and readable stored bytes",
      );
    }

    // --- Step 8: compare the recomputed hash with the hash that was signed ---
    if (recomputedHash === null) {
      record(STEP.compare, "SKIPPED", "no recomputed hash is available");
    } else if (recomputedHash === version.hash) {
      record(STEP.compare, "PASS", `both ${version.hash}`);
    } else {
      record(STEP.compare, "FAIL", `signed ${version.hash}, recomputed ${recomputedHash}`);
      reasons.push("HASH_MISMATCH");
    }
  } catch (error) {
    console.error("Verification failed internally", redactErrorForLog(error));
    record(
      "Verifier error",
      "FAIL",
      `verification could not be completed (${
        error instanceof Error ? error.name : "unknown error"
      }); the result supports no conclusion`,
    );
    reasons.push("INTERNAL_ERROR");
  }

  let reason = REASON_PRECEDENCE.find((candidate) => reasons.includes(candidate));
  if (!reason && !steps.every((step) => step.status === "PASS")) {
    // A step that did not pass without recording why is a verifier bug. Never call it VALID.
    reason = "INTERNAL_ERROR";
  }
  const outcome: VerificationOutcome = reason ? outcomeForReason(reason) : "VALID";

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
      failedSteps: steps
        .filter((step) => step.status !== "PASS")
        .map((step) => `${step.step} [${step.status}]`),
    },
  });

  return { outcome, reason, steps };
}
