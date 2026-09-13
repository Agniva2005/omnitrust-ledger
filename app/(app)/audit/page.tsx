import { ScrollText } from "lucide-react";
import { redirect } from "next/navigation";
import { IntegrityChecker } from "@/app/(app)/audit/integrity-checker";
import { PageHeader } from "@/components/page-header";
import { AuditTimeline } from "@/components/audit-timeline";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { auditEntryCount, listAuditEntries } from "@/lib/audit/log";
import { can } from "@/lib/auth/rbac";
import { getSession } from "@/lib/auth/session";
import { listAuditCheckpoints } from "@/lib/pki/audit-checkpoints";

export const dynamic = "force-dynamic";

export default async function AuditPage() {
  const actor = await getSession();
  if (!actor) redirect("/login");

  const entries = await listAuditEntries(200);
  const total = await auditEntryCount();
  const checkpoints = await listAuditCheckpoints(10);

  return (
    <div className="space-y-6">
      <PageHeader
        icon={ScrollText}
        eyebrow="Integrity"
        title="Audit log"
        description="Append-only and hash-chained: each entry stores SHA-256 of the previous entry's hash concatenated with its own fields, so altering any row breaks the chain from that point on. Signed, time-stamped checkpoints commit to the chain head so that a log whose hashes were recomputed after an edit, or whose newest entries were deleted, is detected too."
      />

      {can(actor.role, "audit:verify") || can(actor.role, "audit:checkpoint") ? (
        <IntegrityChecker
          totalEntries={total}
          canVerify={can(actor.role, "audit:verify")}
          canCheckpoint={can(actor.role, "audit:checkpoint")}
        />
      ) : (
        <Card>
          <CardHeader>
            <CardTitle>Integrity check</CardTitle>
            <CardDescription>
              Role {actor.role} can read the log but not run the integrity check. Sign in as
              admin@demo or verifier@demo to run it.
            </CardDescription>
          </CardHeader>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Signed checkpoints</CardTitle>
          <CardDescription>
            Each commits to the hash of entry <span className="font-mono">seq</span> derived from the
            genesis hash, signed by the audit-signer certificate and time-stamped. Only an admin can
            create one, and only over a log that verifies.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {checkpoints.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No checkpoints yet. Until one exists, a consistent rewrite of the log or deletion of its
              newest entries would not be detectable.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Covers up to seq</TableHead>
                  <TableHead>Head hash</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead>Time-stamp</TableHead>
                  <TableHead>By</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {checkpoints.map((checkpoint) => (
                  <TableRow key={checkpoint.id}>
                    <TableCell className="font-mono text-xs">{checkpoint.seq}</TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {checkpoint.entryHash.slice(0, 16)}...
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">{checkpoint.createdAt}</TableCell>
                    <TableCell>
                      <Badge variant={checkpoint.timestamped ? "secondary" : "outline"}>
                        {checkpoint.timestamped ? "RFC 3161" : "none"}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">{checkpoint.createdBy ?? "-"}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Timeline</CardTitle>
          <CardDescription>
            The newest {entries.length} of {total} entries, grouped by day and coloured by category. Each shows the
            first characters of its chained hash.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <AuditTimeline entries={entries} />
        </CardContent>
      </Card>
    </div>
  );
}
