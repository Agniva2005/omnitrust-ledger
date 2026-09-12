// The verification workflow, report Figure 8 / CLAUDE.md Section 3.
//
// The eight steps below are executed in the order the spec lists them, and every step
// records its own result even after an earlier step has failed, so the UI can show
// which specific check went wrong rather than just a verdict.
import { NotFoundError } from "@/lib/api";
import { requireCapability, type Actor } from "@/lib/auth/rbac";
import { sha256Hex } from "@/lib/crypto/hash";
import { orchestrator } from "@/lib/crypto/orchestrator";
import { DecryptionIntegrityError } from "@/lib/crypto/symmetric";
import { assertAlgorithm } from "@/lib/crypto/types";
import { prisma } from "@/lib/db";
import { assertDocumentState, canTransition } from "@/lib/documents/lifecycle";
import { readBlob } from "@/lib/documents/storage";
import { publicKeyPemFromCertificate } from "@/lib/pki/certificates";
import { validateCertificate } from "@/lib/pki/validation";

export type VerificationReason =
  | "HASH_MISMATCH"
  | "SIGNATURE_INVALID"
  | "CERTIFICATE_EXPIRED"
  | "CERTIFICATE_REVOKED"
  | "CERTIFICATE_CHAIN_INVALID";

export type VerificationResult = {
  outcome: "AUTHENTIC" | "INVALID";
  reason?: VerificationReason;
  steps: { step: string; passed: boolean; detail?: string }[];
};

/** Raised for a document that has no signature yet: neither authentic nor invalid. */
export class DocumentNotSignedError extends Error {
  readonly status = 409;
  constructor(message = "This document has not been signed yet, so there is nothing to verify") {
    super(message);
    this.name = "DocumentNotSignedError";
  }
}

/**
 * Certificate problems outrank content problems, and a hash mismatch outranks an
 * invalid signature: when the bytes have changed the signature necessarily fails too,
 * and "the document was altered" is the more precise diagnosis.
 */
const REASON_PRECEDENCE: VerificationReason[] = [
  "CERTIFICATE_CHAIN_INVALID",
  "CERTIFICATE_EXPIRED",
  "CERTIFICATE_REVOKED",
  "HASH_MISMATCH",
  "SIGNATURE_INVALID",
];

function firstByPrecedence(reasons: VerificationReason[]): VerificationReason | undefined {
  return REASON_PRECEDENCE.find((candidate) => reasons.includes(candidate));
}

export type VerifyOptions = {
  /** Instant to evaluate certificate validity against. Defaults to now. */
  at?: Date;
  /** Verify a specific version instead of the latest. */
  versionNumber?: number;
};

export async function verifyDocument(
  actor: Actor,
  documentId: string,
  options: VerifyOptions = {},
): Promise<VerificationResult> {
  requireCapability(actor, "document:verify");

  const steps: VerificationResult["steps"] = [];
  const reasons: VerificationReason[] = [];
  const at = options.at ?? new Date();

  // --- Step 1: retrieve the document and its current hash ---
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

  steps.push({
    step: "1. Retrieve document and recorded hash",
    passed: true,
    detail: `${document.filename} v${version.versionNumber}, recorded hash ${version.hash}`,
  });

  // --- Step 2: retrieve the signature record ---
  const signature = await prisma.signature.findUnique({
    where: { documentVersionId: version.id },
  });
  if (!signature) throw new DocumentNotSignedError();

  steps.push({
    step: "2. Retrieve signature record",
    passed: true,
    detail: `${signature.algorithm}, ${signature.signatureBytes.length} bytes, signed ${signature.signedAt.toISOString()}`,
  });

  // --- Step 3: retrieve the certificate used to sign ---
  const certificate = await prisma.certificate.findUnique({
    where: { id: signature.certificateId },
  });
  if (!certificate) {
    steps.push({
      step: "3. Retrieve signing certificate",
      passed: false,
      detail: "the certificate referenced by this signature no longer exists",
    });
    return {
      outcome: "INVALID",
      reason: "CERTIFICATE_CHAIN_INVALID",
      steps,
    };
  }

  steps.push({
    step: "3. Retrieve signing certificate",
    passed: true,
    detail: `serial ${certificate.serialNumber}, algorithm ${certificate.algorithm}`,
  });

  // --- Step 4: validate the certificate (chain, validity period, revocation) ---
  const certificateValidation = await validateCertificate(certificate, { at });
  steps.push({
    step: "4. Validate certificate: chain to local CA, validity period, revocation",
    passed: certificateValidation.valid,
    detail: certificateValidation.valid
      ? "chain, validity period and revocation status all pass"
      : certificateValidation.reason,
  });
  for (const check of certificateValidation.checks) {
    steps.push({ step: `4.${check.step}`, passed: check.passed, detail: check.detail });
  }
  if (certificateValidation.reason) reasons.push(certificateValidation.reason);

  // --- Step 5: extract the public key from the certificate ---
  let publicKeyPem: string | null = null;
  try {
    publicKeyPem = publicKeyPemFromCertificate(certificate.certPem);
    steps.push({
      step: "5. Extract public key from certificate",
      passed: true,
      detail: `SubjectPublicKeyInfo extracted from the certificate, not from the key-pair record`,
    });
  } catch (error) {
    steps.push({
      step: "5. Extract public key from certificate",
      passed: false,
      detail: error instanceof Error ? error.message : String(error),
    });
    reasons.push("CERTIFICATE_CHAIN_INVALID");
  }

  // --- Step 6: recompute the hash from the bytes stored right now ---
  let recomputedHash: string | null = null;
  try {
    recomputedHash = sha256Hex(await readBlob(version.storagePath));
    steps.push({
      step: "6. Recompute SHA-256 from the stored bytes",
      passed: true,
      detail: recomputedHash,
    });
  } catch (error) {
    const tampered = error instanceof DecryptionIntegrityError;
    steps.push({
      step: "6. Recompute SHA-256 from the stored bytes",
      passed: false,
      detail: tampered
        ? "the stored blob failed its AES-256-GCM integrity check: the bytes on disk are not the bytes that were written"
        : error instanceof Error
          ? error.message
          : String(error),
    });
    reasons.push("HASH_MISMATCH");
  }

  // --- Step 7: verify the signature against the recomputed hash ---
  let signatureValid = false;
  if (publicKeyPem && recomputedHash) {
    try {
      signatureValid = await orchestrator.verify({
        algorithm: assertAlgorithm(signature.algorithm),
        digest: Buffer.from(recomputedHash, "hex"),
        signature: signature.signatureBytes,
        publicKeyPem,
      });
      steps.push({
        step: "7. Verify signature against the recomputed hash",
        passed: signatureValid,
        detail: `algorithm ${signature.algorithm}, resolved from the signature record`,
      });
    } catch (error) {
      // A key of the wrong type for this algorithm is a failed verification, not a
      // server error: substituting another algorithm's public key lands here.
      steps.push({
        step: "7. Verify signature against the recomputed hash",
        passed: false,
        detail: `${signature.algorithm} verification rejected the key or signature: ${
          error instanceof Error ? error.message : String(error)
        }`,
      });
    }
    if (!signatureValid) reasons.push("SIGNATURE_INVALID");
  } else {
    steps.push({
      step: "7. Verify signature against the recomputed hash",
      passed: false,
      detail: "skipped: no usable public key or no readable stored bytes",
    });
    reasons.push("SIGNATURE_INVALID");
  }

  // --- Step 8: compare the recomputed hash with the hash that was actually signed ---
  const hashesMatch = recomputedHash !== null && recomputedHash === version.hash;
  steps.push({
    step: "8. Compare recomputed hash with the hash that was signed",
    passed: hashesMatch,
    detail: hashesMatch
      ? `both ${version.hash}`
      : `signed ${version.hash}, recomputed ${recomputedHash ?? "unavailable"}`,
  });
  if (!hashesMatch) reasons.push("HASH_MISMATCH");

  const outcome: VerificationResult["outcome"] =
    reasons.length === 0 && signatureValid && hashesMatch ? "AUTHENTIC" : "INVALID";

  if (outcome === "AUTHENTIC") {
    const current = assertDocumentState(document.status);
    if (canTransition(current, "VERIFIED")) {
      await prisma.document.update({ where: { id: document.id }, data: { status: "VERIFIED" } });
    }
  }

  return {
    outcome,
    reason: outcome === "AUTHENTIC" ? undefined : firstByPrecedence(reasons),
    steps,
  };
}
