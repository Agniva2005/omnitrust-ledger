// Security Lab: the entry point the application uses. Admin-only, one run at a time, audited.
// Record counts in the application's own database are taken before and after every run, as
// evidence that the attack touched only its sandbox.
import { BadRequestError, ConflictError, NotFoundError } from "@/lib/api";
import { appendAuditEntry } from "@/lib/audit/log";
import { requireCapability, type Actor } from "@/lib/auth/rbac";
import { prisma } from "@/lib/db";
import { readBlob } from "@/lib/documents/storage";
import { SCENARIOS, isScenarioId } from "@/lib/security-lab/catalog";
import { runScenarioInSandbox, type SandboxSubject } from "@/lib/security-lab/sandbox";

let running = false;

export function listScenarios(actor: Actor) {
  requireCapability(actor, "lab:run");
  return SCENARIOS;
}

async function productionCounts() {
  const [documents, versions, signatures, certificates, revocationLists, auditEntries, auditCheckpoints] = await Promise.all([
    prisma.document.count(),
    prisma.documentVersion.count(),
    prisma.signature.count(),
    prisma.certificate.count(),
    prisma.revocationList.count(),
    prisma.auditLogEntry.count(),
    prisma.auditCheckpoint.count(),
  ]);
  const head = await prisma.auditLogEntry.findFirst({ orderBy: { seq: "desc" }, select: { entryHash: true } });
  return { documents, versions, signatures, certificates, revocationLists, auditEntries, auditCheckpoints, auditHead: head?.entryHash ?? null };
}

/**
 * Decrypts the latest version of a chosen document so the sandbox can use it as the subject.
 * Read-only: the sandbox never writes back, and only this plaintext copy crosses the boundary.
 */
async function subjectFor(documentId: string): Promise<SandboxSubject> {
  const document = await prisma.document.findUnique({
    where: { id: documentId },
    include: { versions: { orderBy: { versionNumber: "desc" }, take: 1 } },
  });
  const version = document?.versions[0];
  if (!document || !version) throw new NotFoundError("Document not found");
  return { bytes: await readBlob(version.storagePath), filename: document.filename, mimeType: document.mimeType };
}

export async function runSecurityLab(actor: Actor, scenarioId: unknown, documentId?: unknown) {
  requireCapability(actor, "lab:run");
  if (!isScenarioId(scenarioId)) throw new BadRequestError("Unknown Security Lab scenario");
  if (running) throw new ConflictError("A Security Lab run is already in progress");

  let chosen: SandboxSubject | undefined;
  if (typeof documentId === "string" && documentId.length > 0) {
    if (!SCENARIOS.find((scenario) => scenario.id === scenarioId)?.acceptsSubject) {
      throw new BadRequestError("This scenario does not act on a document, so it cannot take one as its subject");
    }
    chosen = await subjectFor(documentId);
  }

  running = true;
  try {
    const before = await productionCounts();
    const run = await runScenarioInSandbox(scenarioId, chosen);
    const after = await productionCounts();
    const productionUntouched = JSON.stringify(before) === JSON.stringify(after);

    await appendAuditEntry({
      actorUserId: actor.userId,
      action: "SECURITY_LAB_RUN",
      targetType: "SecurityLabScenario",
      targetId: scenarioId,
      metadata: {
        outcome: run.result.outcome,
        durationMs: run.durationMs,
        sandboxRemoved: run.sandboxRemoved,
        productionUntouched,
        ...(chosen ? { subjectDocumentId: documentId as string, subjectFilename: chosen.filename } : {}),
      },
    });

    return {
      ...run,
      subject: chosen ? { filename: chosen.filename, byteLength: chosen.bytes.length } : null,
      production: { before, after, untouched: productionUntouched },
    };
  } finally {
    running = false;
  }
}
