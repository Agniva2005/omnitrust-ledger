// Document Management layer: the signing action.
//
// Composes three layers without doing any crypto itself: it asks the PKI layer for
// the certificate and key, the orchestrator for the signature, and the lifecycle for
// the state transition.
import type { Signature } from "@prisma/client";
import { ConflictError, NotFoundError } from "@/lib/api";
import { appendAuditEntry } from "@/lib/audit/log";
import { AuthorizationError, requireCapability, type Actor } from "@/lib/auth/rbac";
import { orchestrator } from "@/lib/crypto/orchestrator";
import { assertAlgorithm } from "@/lib/crypto/types";
import { prisma } from "@/lib/db";
import { assertPath, assertDocumentState } from "@/lib/documents/lifecycle";
import { latestVersion, recomputeVersionHash } from "@/lib/documents/service";
import { privateKeyPemFor } from "@/lib/pki/certificates";
import { validateCertificate } from "@/lib/pki/validation";

export type SignDocumentInput = {
  actor: Actor;
  documentId: string;
  certificateId: string;
};

export type SignDocumentResult = {
  signature: Signature;
  documentStatus: string;
  signedHash: string;
};

function isUniqueViolation(error: unknown): boolean {
  return (error as { code?: unknown } | null)?.code === "P2002";
}

/**
 * Signs the current version's hash. The payload is the raw 32 bytes of that
 * SHA-256, so the signature is over the document's content digest and nothing else.
 */
export async function signDocument(input: SignDocumentInput): Promise<SignDocumentResult> {
  requireCapability(input.actor, "document:sign");

  const document = await prisma.document.findUnique({ where: { id: input.documentId } });
  if (!document) throw new NotFoundError("Document not found");

  const version = await latestVersion(document.id);
  const alreadySigned = `Version ${version.versionNumber} is already signed. Upload a new version to sign again.`;

  const existing = await prisma.signature.findUnique({
    where: { documentVersionId: version.id },
  });
  if (existing) throw new ConflictError(alreadySigned);

  const certificate = await prisma.certificate.findUnique({
    where: { id: input.certificateId },
    include: { keyPair: true },
  });
  if (!certificate) throw new NotFoundError("Certificate not found");

  if (certificate.subjectUserId !== input.actor.userId) {
    throw new AuthorizationError("You can only sign with a certificate issued to you");
  }

  const validation = await validateCertificate(certificate);
  if (!validation.valid) {
    throw new ConflictError(
      `Refusing to sign with a certificate that does not validate: ${validation.reason}`,
    );
  }

  // Integrity precondition: never sign a hash that no longer describes the stored
  // bytes, otherwise the signature would attest to something that was never there.
  const recomputed = await recomputeVersionHash(version);
  if (recomputed !== version.hash) {
    throw new ConflictError(
      "Stored bytes no longer match the recorded hash for this version; refusing to sign",
    );
  }

  const algorithm = assertAlgorithm(certificate.algorithm);
  const digest = Buffer.from(version.hash, "hex");

  const signatureBytes = await orchestrator.sign({
    algorithm,
    digest,
    privateKeyPem: privateKeyPemFor(certificate.keyPair),
  });

  // The signature row and the lifecycle transition commit together or not at all. The
  // unique constraint on documentVersionId settles a race between two signers.
  let committed: { signature: Signature; documentStatus: string };
  try {
    committed = await prisma.$transaction(async (tx) => {
      const signature = await tx.signature.create({
        data: {
          documentVersionId: version.id,
          certificateId: certificate.id,
          algorithm,
          signatureBytes: new Uint8Array(signatureBytes),
          signedByUserId: input.actor.userId,
        },
      });
      const advanced = await tx.document.update({
        where: { id: document.id },
        data: {
          status: assertPath([assertDocumentState(document.status), "SIGNED", "STORED"]),
        },
      });
      return { signature, documentStatus: advanced.status };
    });
  } catch (error) {
    if (isUniqueViolation(error)) throw new ConflictError(alreadySigned);
    throw error;
  }

  await appendAuditEntry({
    actorUserId: input.actor.userId,
    action: "DOCUMENT_SIGNED",
    targetType: "Document",
    targetId: document.id,
    metadata: {
      algorithm,
      certificateSerial: certificate.serialNumber,
      signatureByteLength: signatureBytes.length,
      signedHash: version.hash,
      versionNumber: version.versionNumber,
    },
  });

  return { ...committed, signedHash: version.hash };
}

export async function signaturesForDocument(documentId: string) {
  return prisma.signature.findMany({
    where: { documentVersion: { documentId } },
    orderBy: { signedAt: "desc" },
    include: {
      documentVersion: { select: { versionNumber: true, hash: true } },
      certificate: { select: { id: true, serialNumber: true, algorithm: true, status: true } },
      signedBy: { select: { email: true } },
    },
  });
}
