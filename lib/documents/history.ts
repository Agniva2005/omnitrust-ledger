// A document's own history, read back out of the audit log.
//
// Nothing here is a second record: every row is an existing audit entry, carrying the sequence
// number and hash it has in the chain. That is the point — the page shows what happened to a
// document, and each line can be checked against the log's integrity walk rather than believed.
import { prisma } from "@/lib/db";

export type EventTone = "neutral" | "good" | "bad";

export type DocumentEvent = {
  seq: number;
  at: string;
  action: string;
  actor: string | null;
  headline: string;
  summary: string;
  tone: EventTone;
  outcome: string | null;
  reason: string | null;
  entryHash: string;
  prevHash: string;
};

type Metadata = Record<string, unknown>;

const text = (value: unknown): string | null => (typeof value === "string" ? value : null);
const count = (value: unknown): number | null => (typeof value === "number" ? value : null);
const short = (hash: unknown): string => (typeof hash === "string" ? `${hash.slice(0, 12)}…` : "—");

/** One readable line per action, using whatever that action actually recorded. */
function describe(action: string, metadata: Metadata): { headline: string; summary: string; tone: EventTone } {
  switch (action) {
    case "DOCUMENT_UPLOADED":
      return {
        headline: "Uploaded",
        summary: `${text(metadata.filename) ?? "The document"} was stored and hashed to ${short(metadata.hash)}`,
        tone: "neutral",
      };
    case "DOCUMENT_VERSION_ADDED":
      return {
        headline: `Version ${count(metadata.versionNumber) ?? ""} added`.trim(),
        summary: `New content stored, hashing to ${short(metadata.hash)}. Earlier versions keep their own hashes and signatures.`,
        tone: "neutral",
      };
    case "DOCUMENT_SIGNED":
      return {
        headline: "Signed",
        summary: `${text(metadata.algorithm) ?? "A signature"} over ${short(metadata.signedHash)}, under certificate ${short(metadata.certificateSerial)}`,
        tone: "good",
      };
    case "DOCUMENT_VERIFIED": {
      const outcome = text(metadata.outcome) ?? "";
      const reason = text(metadata.reason);
      return {
        headline: "Verified",
        summary: reason ? `${outcome} — ${reason}` : outcome,
        tone: outcome === "VALID" ? "good" : outcome === "INVALID" ? "bad" : "neutral",
      };
    }
    case "DOCUMENT_EXPORTED":
      return { headline: "Exported", summary: `${text(metadata.part) ?? "An artefact"} was downloaded`, tone: "neutral" };
    case "DEMO_CONTENT_TAMPERED":
      return {
        headline: "Stored bytes replaced",
        summary: `The bytes on disk were swapped for different content. The recorded hash stayed ${short(metadata.signedHash)}, so it no longer describes what is stored.`,
        tone: "bad",
      };
    case "DEMO_CIPHERTEXT_TAMPERED":
      return {
        headline: "Ciphertext altered",
        summary: `One bit of the encrypted blob was flipped at byte ${count(metadata.byteOffset) ?? "?"}, which the AES-GCM tag rejects on read.`,
        tone: "bad",
      };
    case "DEMO_SIGNATURE_TAMPERED":
      return {
        headline: "Signature altered",
        summary: `The stored signature changed from ${text(metadata.firstBytesBefore) ?? "?"}… to ${text(metadata.firstBytesAfter) ?? "?"}…, keeping its ${count(metadata.byteLength) ?? "?"}-byte length.`,
        tone: "bad",
      };
    case "DEMO_TAMPER_RESTORED":
      return {
        headline: "Restored",
        summary: `The original ${text(metadata.restored) ?? "bytes"} were put back exactly as they were.`,
        tone: "good",
      };
    default:
      return { headline: action, summary: "", tone: "neutral" };
  }
}

/**
 * Every audit entry about this document, oldest first. Entries either target the document
 * directly or name it in their metadata, which is how the version- and signature-scoped
 * actions are found.
 */
export async function documentHistory(documentId: string): Promise<DocumentEvent[]> {
  const entries = await prisma.auditLogEntry.findMany({
    where: {
      OR: [
        { targetType: "Document", targetId: documentId },
        { metadataJson: { contains: documentId } },
      ],
    },
    orderBy: { seq: "asc" },
    include: { actor: { select: { email: true } } },
  });

  return entries.map((entry) => {
    let metadata: Metadata = {};
    try {
      metadata = JSON.parse(entry.metadataJson) as Metadata;
    } catch {
      metadata = {};
    }
    const { headline, summary, tone } = describe(entry.action, metadata);
    return {
      seq: entry.seq,
      at: entry.createdAt.toISOString(),
      action: entry.action,
      actor: entry.actor?.email ?? null,
      headline,
      summary,
      tone,
      outcome: text(metadata.outcome),
      reason: text(metadata.reason),
      entryHash: entry.entryHash,
      prevHash: entry.prevHash,
    };
  });
}
