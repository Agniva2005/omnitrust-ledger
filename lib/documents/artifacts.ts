// The bytes behind a document, made readable.
//
// A signature is a BLOB column and a stored document is an encrypted file, so both are
// invisible in an interface that only names them. This exposes enough of each to point at on
// screen — and to watch change when something is altered — without ever handing back key
// material or the whole plaintext.
import fs from "node:fs/promises";
import { absolutePath } from "@/lib/documents/storage";
import { prisma } from "@/lib/db";

/** 12-byte IV and 16-byte GCM tag, as lib/crypto/symmetric.ts writes them. */
const IV_BYTES = 12;
const TAG_BYTES = 16;

/** How much ciphertext to show: enough to look like noise, short enough to read. */
const CIPHERTEXT_PREVIEW = 32;

export type SignatureArtifact = {
  versionNumber: number;
  algorithm: string;
  byteLength: number;
  hex: string;
  timestampedAt: string | null;
  timestampTokenBytes: number | null;
  cmsBytes: number | null;
};

export type BlobArtifact = {
  versionNumber: number;
  storagePath: string;
  fileBytes: number;
  iv: string;
  tag: string;
  ciphertextHead: string;
  ciphertextBytes: number;
  unreadable: string | null;
};

export type DocumentArtifacts = { signatures: SignatureArtifact[]; blobs: BlobArtifact[] };

export async function documentArtifacts(documentId: string): Promise<DocumentArtifacts> {
  const versions = await prisma.documentVersion.findMany({
    where: { documentId },
    orderBy: { versionNumber: "desc" },
    include: { signatures: true },
  });

  const signatures: SignatureArtifact[] = [];
  const blobs: BlobArtifact[] = [];

  for (const version of versions) {
    for (const signature of version.signatures) {
      const bytes = Buffer.from(signature.signatureBytes);
      signatures.push({
        versionNumber: version.versionNumber,
        algorithm: signature.algorithm,
        byteLength: bytes.length,
        hex: bytes.toString("hex"),
        timestampedAt: signature.timestampedAt?.toISOString() ?? null,
        timestampTokenBytes: signature.timestampToken ? Buffer.from(signature.timestampToken).length : null,
        cmsBytes: signature.cmsSignature ? Buffer.from(signature.cmsSignature).length : null,
      });
    }

    try {
      const raw = await fs.readFile(absolutePath(version.storagePath));
      blobs.push({
        versionNumber: version.versionNumber,
        storagePath: version.storagePath,
        fileBytes: raw.length,
        iv: raw.subarray(0, IV_BYTES).toString("hex"),
        tag: raw.subarray(IV_BYTES, IV_BYTES + TAG_BYTES).toString("hex"),
        ciphertextHead: raw.subarray(IV_BYTES + TAG_BYTES, IV_BYTES + TAG_BYTES + CIPHERTEXT_PREVIEW).toString("hex"),
        ciphertextBytes: Math.max(0, raw.length - IV_BYTES - TAG_BYTES),
        unreadable: null,
      });
    } catch (error) {
      blobs.push({
        versionNumber: version.versionNumber,
        storagePath: version.storagePath,
        fileBytes: 0,
        iv: "",
        tag: "",
        ciphertextHead: "",
        ciphertextBytes: 0,
        unreadable: error instanceof Error ? error.message : "The file could not be read",
      });
    }
  }

  return { signatures, blobs };
}
