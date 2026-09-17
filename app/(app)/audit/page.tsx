import { ScrollText } from "lucide-react";
import { redirect } from "next/navigation";
import { AuditTamperPanel } from "@/app/(app)/audit/audit-tamper-panel";
import { IntegrityChecker } from "@/app/(app)/audit/integrity-checker";
import { PageHeader } from "@/components/page-header";
import { AuditTimeline } from "@/components/audit-timeline";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { auditTamperState } from "@/lib/audit/demo-tamper";
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
  const tamper = can(actor.role, "demo:tamper") ? await auditTamperState() : null;
  const maxSeq = entries[0]?.seq ?? 0;

  return (
    <div className="space-y-6">
      <PageHeader
        icon={ScrollText}
        eyebrow="Integrity"
        title="Audit log"
        description="Append-only and hash-chained: each entry stores SHA-256 of the previous entry's hash concatenated with its own fields, so altering any row breaks the chain from that point on. Signed, time-stamped checkpoints commit to the chain head so that a log whose hashes were recomputed after an edit, or whose newest entries were deleted, is detected too."
      />

      <div className="grid items-start gap-6 2xl:grid-cols-[minmax(0,1fr)_30rem] 3xl:grid-cols-[minmax(0,1fr)_34rem]">
      {/* Right rail on desktop: the check and the checkpoints stay in view while the timeline scrolls. */}
      <div className="min-w-0 space-y-6 2xl:sticky 2xl:top-20 2xl:col-start-2 2xl:row-start-1 2xl:max-h-[calc(100vh-6rem)] 2xl:overflow-y-auto 2xl:pb-1">
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

      {tamper && maxSeq > 0 && <AuditTamperPanel initialState={tamper} maxSeq={maxSeq} />}

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
            <ol aria-label="Signed checkpoints" className="divide-y overflow-hidden rounded-lg border">
              {checkpoints.map((checkpoint) => (
                <li key={checkpoint.id} className="flex items-start gap-3 px-3 py-2.5 text-sm">
                  <span className="grid h-8 min-w-[2.5rem] shrink-0 place-items-center rounded-md border bg-muted/40 px-1.5 font-mono text-xs" title="Covers entries up to this sequence number">
                    #{checkpoint.seq}
                  </span>
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-xs text-muted-foreground" title={checkpoint.entryHash}>
                        head {checkpoint.entryHash.slice(0, 16)}…
                      </span>
                      <Badge variant={checkpoint.timestamped ? "secondary" : "outline"}>{checkpoint.timestamped ? "RFC 3161" : "no time-stamp"}</Badge>
                    </div>
                    <div className="mt-0.5 text-xs text-muted-foreground">
                      {checkpoint.createdAt} · by {checkpoint.createdBy ?? "-"}
                    </div>
                  </div>
                </li>
              ))}
            </ol>
          )}
        </CardContent>
      </Card>
      </div>

      <Card className="min-w-0 2xl:col-start-1 2xl:row-start-1">
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
    </div>
  );
}
