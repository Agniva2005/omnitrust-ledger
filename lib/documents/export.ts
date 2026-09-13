// Document Management layer: exporting a signed document for verification outside this app.
//
// Three parts are enough for an external verifier: the document bytes, the detached CMS
// signature (which carries the signer's and the CA's certificates), and the trust anchor,
// published separately at /api/pki/ca. Every export is audited.
import { ConflictError, NotFoundError } from "@/lib/api";
import { appendAuditEntry } from "@/lib/audit/log";
import { requireCapability, type Actor } from "@/lib/auth/rbac";
import { prisma } from "@/lib/db";
import { readBlob } from "@/lib/documents/storage";

export const EXPORT_PARTS = ["cms", "content", "certificate"] as const;
export type ExportPart = (typeof EXPORT_PARTS)[number];

export function isExportPart(value: unknown): value is ExportPart {
  return typeof value === "string" && (EXPORT_PARTS as readonly string[]).includes(value);
}

export type ExportedFile = { bytes: Buffer; contentType: string; filename: string };

/** A filename safe inside a Content-Disposition header and on any filesystem. */
export function safeFilename(filename: string): string {
  const cleaned = filename.replace(/[^A-Za-z0-9._-]/g, "_").replace(/^\.+/, "").slice(0, 120);
  return cleaned || "document";
}

export async function exportSignedDocument(
  actor: Actor,
  documentId: string,
  part: ExportPart,
  versionNumber?: number,
): Promise<ExportedFile> {
  requireCapability(actor, "document:read");

  const document = await prisma.document.findUnique({
    where: { id: documentId },
    include: { versions: { orderBy: { versionNumber: "desc" } } },
  });
  if (!document) throw new NotFoundError("Document not found");

  const version =
    versionNumber === undefined
      ? document.versions[0]
      : document.versions.find((candidate) => candidate.versionNumber === versionNumber);
  if (!version) throw new NotFoundError("Document version not found");

  const base = `${safeFilename(document.filename)}.v${version.versionNumber}`;
  let file: ExportedFile;

  if (part === "content") {
    // Served as opaque bytes so a browser never renders uploaded content as a page.
    file = {
      bytes: await readBlob(version.storagePath),
      contentType: "application/octet-stream",
      filename: safeFilename(document.filename),
    };
  } else {
    const signature = await prisma.signature.findUnique({
      where: { documentVersionId: version.id },
      include: { certificate: true },
    });
    if (!signature) throw new NotFoundError(`Version ${version.versionNumber} has not been signed`);

    if (part === "certificate") {
      file = {
        bytes: Buffer.from(signature.certificate.certPem),
        contentType: "application/x-pem-file",
        filename: `${base}.signer.pem`,
      };
    } else {
      if (!signature.cmsSignature) {
        throw new ConflictError(
          "This signature was made before CMS export was available, so there is no CMS signature to export",
        );
      }
      file = {
        bytes: Buffer.from(signature.cmsSignature),
        contentType: "application/pkcs7-signature",
        filename: `${base}.p7s`,
      };
    }
  }

  await appendAuditEntry({
    actorUserId: actor.userId,
    action: "DOCUMENT_EXPORTED",
    targetType: "Document",
    targetId: document.id,
    metadata: { part, versionNumber: version.versionNumber, byteLength: file.bytes.length },
  });

  return file;
}
