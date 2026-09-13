// Dashboard data: every figure is a count or a record read from the database at request time.
// Nothing is estimated. Where a value is only what was stored (for example the latest CRL row),
// the name says so; authenticated checks stay on their own pages.
import { listAuditEntries } from "@/lib/audit/log";
import { requireCapability, type Actor } from "@/lib/auth/rbac";
import { orchestrator } from "@/lib/crypto/orchestrator";
import { prisma } from "@/lib/db";
import { getRootCa } from "@/lib/pki/ca";
import { markExpiredCertificates, parseCertificate } from "@/lib/pki/certificates";

function counted<T extends string>(rows: { key: T; count: number }[]) {
  return rows.sort((a, b) => b.count - a.count);
}

export async function systemOverview(actor: Actor) {
  requireCapability(actor, "document:read");
  const now = new Date();
  // The same Figure 6 ACTIVE -> EXPIRED sweep the certificates page runs, so the dashboard's
  // status counts agree with it instead of reporting a lapsed certificate as active.
  await markExpiredCertificates(now);

  const [documentGroups, signatureGroups, certificateGroups, signatureTotal, timestampedSignatures, cmsSignatures] = await Promise.all([
    prisma.document.groupBy({ by: ["status"], _count: { _all: true } }),
    prisma.signature.groupBy({ by: ["algorithm"], _count: { _all: true } }),
    prisma.certificate.groupBy({ by: ["status"], _count: { _all: true } }),
    prisma.signature.count(),
    prisma.signature.count({ where: { timestampToken: { not: null } } }),
    prisma.signature.count({ where: { cmsSignature: { not: null } } }),
  ]);

  const [auditEntries, latestCheckpoint, latestCrl, tsa, ca, checkpointCount, anchoredLeaves, anchorBatches] = await Promise.all([
    prisma.auditLogEntry.count(),
    prisma.auditCheckpoint.findFirst({ orderBy: { seq: "desc" } }),
    prisma.revocationList.findFirst({ orderBy: { crlNumber: "desc" } }),
    prisma.timestampAuthority.findFirst({ where: { status: "ACTIVE" }, orderBy: { createdAt: "desc" } }),
    getRootCa().catch(() => null),
    prisma.auditCheckpoint.count(),
    prisma.anchorLeaf.count(),
    prisma.anchorBatch.count(),
  ]);

  const verificationEntries = await prisma.auditLogEntry.findMany({
    where: { action: "DOCUMENT_VERIFIED" },
    orderBy: { seq: "desc" },
    take: 8,
    include: { actor: { select: { email: true } } },
  });
  const documents = await prisma.document.findMany({
    where: { id: { in: verificationEntries.map((entry) => entry.targetId) } },
    select: { id: true, filename: true },
  });
  const filenames = new Map(documents.map((document) => [document.id, document.filename]));

  return {
    generatedAt: now.toISOString(),
    documents: {
      total: documentGroups.reduce((sum, group) => sum + group._count._all, 0),
      byStatus: counted(documentGroups.map((group) => ({ key: group.status, count: group._count._all }))),
    },
    signatures: {
      total: signatureTotal,
      timestamped: timestampedSignatures,
      withCms: cmsSignatures,
      byAlgorithm: counted(
        signatureGroups.map((group) => ({ key: orchestrator.displayName(group.algorithm), count: group._count._all })),
      ),
    },
    certificates: {
      total: certificateGroups.reduce((sum, group) => sum + group._count._all, 0),
      byStatus: counted(certificateGroups.map((group) => ({ key: group.status, count: group._count._all }))),
    },
    trustServices: {
      ca: ca
        ? { name: ca.name, algorithm: orchestrator.displayName(ca.algorithm), notAfter: parseCertificate(ca.certPem).notAfter.toISOString() }
        : null,
      tsa: tsa ? { name: tsa.name, algorithm: orchestrator.displayName(tsa.algorithm), expiresAt: tsa.expiresAt.toISOString() } : null,
      latestCrl: latestCrl
        ? {
            crlNumber: latestCrl.crlNumber,
            thisUpdate: latestCrl.thisUpdate.toISOString(),
            nextUpdate: latestCrl.nextUpdate.toISOString(),
            withinValidity: latestCrl.nextUpdate > now,
          }
        : null,
    },
    integrity: {
      auditEntries,
      checkpoints: checkpointCount,
      latestCheckpoint: latestCheckpoint ? { seq: latestCheckpoint.seq, createdAt: latestCheckpoint.createdAt.toISOString() } : null,
      entriesAfterLatestCheckpoint: latestCheckpoint ? Math.max(0, auditEntries - latestCheckpoint.seq) : auditEntries,
      anchorBatches,
      anchoredItems: anchoredLeaves,
    },
    recentVerifications: verificationEntries.map((entry) => {
      const metadata = JSON.parse(entry.metadataJson) as { outcome?: string; reason?: string | null; algorithm?: string };
      return {
        seq: entry.seq,
        documentId: entry.targetId,
        filename: filenames.get(entry.targetId) ?? "(deleted document)",
        outcome: metadata.outcome ?? "UNKNOWN",
        reason: metadata.reason ?? null,
        algorithm: metadata.algorithm ? orchestrator.displayName(metadata.algorithm) : null,
        by: entry.actor?.email ?? null,
        at: entry.createdAt.toISOString(),
      };
    }),
    recentActivity: (await listAuditEntries(10)).map((entry) => ({
      seq: entry.seq,
      action: entry.action,
      targetType: entry.targetType,
      by: entry.actor?.email ?? null,
      at: entry.createdAt.toISOString(),
    })),
  };
}

export type SystemOverview = Awaited<ReturnType<typeof systemOverview>>;
