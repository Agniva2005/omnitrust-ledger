import { Activity, Anchor, BadgeCheck, Clock, FileSignature, FileText, KeyRound, LayoutDashboard, ListChecks, ScrollText, ShieldCheck, Upload } from "lucide-react";
import Link from "next/link";
import { redirect } from "next/navigation";
import { DistributionBars } from "@/components/distribution-bar";
import { PageHeader } from "@/components/page-header";
import { StatCard } from "@/components/stat-card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { VerdictBadge } from "@/components/verdict-badge";
import { can, capabilitiesFor } from "@/lib/auth/rbac";
import { getSession } from "@/lib/auth/session";
import { systemOverview } from "@/lib/dashboard/overview";
import { cn } from "@/lib/utils";

export const dynamic = "force-dynamic";

function when(iso: string) {
  return iso.replace("T", " ").slice(0, 19);
}

function ServiceRow({ icon: Icon, name, detail, state }: { icon: typeof ShieldCheck; name: string; detail: React.ReactNode; state: "ok" | "attention" | "absent" }) {
  return (
    <li className="flex items-start gap-3 py-3 first:pt-0 last:pb-0">
      <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg border bg-muted/40 text-muted-foreground">
        <Icon aria-hidden className="h-4 w-4" />
      </span>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2 text-sm font-medium">
          {name}
          <span
            aria-label={state === "ok" ? "operational" : state === "attention" ? "needs attention" : "not created"}
            className={cn("h-1.5 w-1.5 rounded-full", state === "ok" ? "bg-success" : state === "attention" ? "bg-warning" : "bg-muted-foreground/40")}
          />
        </div>
        <div className="mt-0.5 text-xs leading-relaxed text-muted-foreground">{detail}</div>
      </div>
    </li>
  );
}

export default async function DashboardPage() {
  const actor = await getSession();
  if (!actor) redirect("/login");

  const overview = await systemOverview(actor);
  const { trustServices, integrity } = overview;

  return (
    <div className="space-y-8">
      <PageHeader
        icon={LayoutDashboard}
        title="Dashboard"
        description={`Signed in as ${actor.email} (${actor.role}). Every figure below is read from the database for this request.`}
        actions={
          can(actor.role, "document:upload") ? (
            <Button asChild>
              <Link href="/documents/upload">
                <Upload aria-hidden /> Upload document
              </Link>
            </Button>
          ) : null
        }
      />

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Documents" value={overview.documents.total} icon={FileText} href="/documents" detail={`${overview.documents.byStatus.length} lifecycle state${overview.documents.byStatus.length === 1 ? "" : "s"} in use`} />
        <StatCard
          label="Signatures"
          value={overview.signatures.total}
          icon={FileSignature}
          tone="pq"
          href="/documents"
          detail={`${overview.signatures.timestamped} time-stamped, ${overview.signatures.withCms} with a CMS export`}
        />
        <StatCard
          label="Certificates"
          value={overview.certificates.total}
          icon={ShieldCheck}
          tone="success"
          href="/certificates"
          detail={overview.certificates.byStatus.map((row) => `${row.count} ${row.key.toLowerCase()}`).join(", ") || "none issued"}
        />
        <StatCard
          label="Audit entries"
          value={integrity.auditEntries}
          icon={ScrollText}
          tone={integrity.latestCheckpoint ? "hybrid" : "warning"}
          href="/audit"
          detail={
            integrity.latestCheckpoint
              ? `${integrity.checkpoints} signed checkpoint${integrity.checkpoints === 1 ? "" : "s"}; ${integrity.entriesAfterLatestCheckpoint} entries since the latest`
              : "no signed checkpoint yet"
          }
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card>
          <CardHeader>
            <CardTitle>Documents by lifecycle state</CardTitle>
            <CardDescription>State machine from report Figure 4.</CardDescription>
          </CardHeader>
          <CardContent>
            <DistributionBars rows={overview.documents.byStatus} empty="No documents yet." />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Signatures by algorithm</CardTitle>
            <CardDescription>
              <Link href="/algorithms" className="inline-flex items-center gap-1 text-primary hover:underline">
                <KeyRound aria-hidden className="h-3.5 w-3.5" /> Compare algorithms
              </Link>
            </CardDescription>
          </CardHeader>
          <CardContent>
            <DistributionBars rows={overview.signatures.byAlgorithm} empty="No signatures yet." />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Trust services</CardTitle>
            <CardDescription>Local and demo-grade; trusted by nothing outside this installation.</CardDescription>
          </CardHeader>
          <CardContent>
            <ul className="divide-y">
              <ServiceRow
                icon={ShieldCheck}
                name="Root CA"
                state={trustServices.ca ? "ok" : "absent"}
                detail={trustServices.ca ? `${trustServices.ca.algorithm}, valid until ${trustServices.ca.notAfter.slice(0, 10)}` : "not created"}
              />
              <ServiceRow
                icon={Clock}
                name="Time-Stamp Authority"
                state={trustServices.tsa ? "ok" : "absent"}
                detail={trustServices.tsa ? `${trustServices.tsa.algorithm}, RFC 3161, valid until ${trustServices.tsa.expiresAt.slice(0, 10)}` : "created on first time-stamp"}
              />
              <ServiceRow
                icon={ListChecks}
                name="Latest issued CRL"
                state={trustServices.latestCrl ? (trustServices.latestCrl.withinValidity ? "ok" : "attention") : "absent"}
                detail={
                  trustServices.latestCrl
                    ? `#${trustServices.latestCrl.crlNumber}, issued ${when(trustServices.latestCrl.thisUpdate)}, ${trustServices.latestCrl.withinValidity ? "within its validity" : "past its next update"}`
                    : "none issued yet"
                }
              />
              <ServiceRow
                icon={Anchor}
                name="Anchoring"
                state={integrity.anchorBatches > 0 ? "ok" : "absent"}
                detail={
                  <>
                    {integrity.anchorBatches} batch{integrity.anchorBatches === 1 ? "" : "es"} covering {integrity.anchoredItems} item{integrity.anchoredItems === 1 ? "" : "s"} recorded.{" "}
                    <Link href="/anchoring" className="text-primary hover:underline">
                      Whether the chain that holds them is still running
                    </Link>{" "}
                    decides if they can be checked.
                  </>
                }
              />
            </ul>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <BadgeCheck aria-hidden className="h-4 w-4 text-primary" /> Recent verifications
            </CardTitle>
            <CardDescription>From the audit log. VALID, INVALID, UNVERIFIABLE and ERROR are kept distinct.</CardDescription>
          </CardHeader>
          <CardContent>
            {overview.recentVerifications.length === 0 ? (
              <p className="rounded-lg border border-dashed px-4 py-8 text-center text-sm text-muted-foreground">No verifications have been run yet.</p>
            ) : (
              <ul className="divide-y">
                {overview.recentVerifications.map((entry) => (
                  <li key={entry.seq} className="flex flex-wrap items-center gap-x-3 gap-y-1 py-2.5 text-sm">
                    <VerdictBadge outcome={entry.outcome} />
                    <Link href={`/documents/${entry.documentId}`} className="min-w-0 truncate font-medium hover:underline">
                      {entry.filename}
                    </Link>
                    {entry.reason && <span className="font-mono text-[11px] text-muted-foreground">{entry.reason}</span>}
                    <span className="ml-auto font-mono text-[11px] text-muted-foreground">{when(entry.at)}</span>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Activity aria-hidden className="h-4 w-4 text-primary" /> Recent activity
            </CardTitle>
            <CardDescription>
              The newest entries of the hash-chained audit log.{" "}
              <Link href="/audit" className="text-primary hover:underline">
                Full timeline
              </Link>
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ol className="relative space-y-3 border-l pl-5">
              {overview.recentActivity.map((entry) => {
                const alarming = entry.action.includes("FAILED") || entry.action.includes("REVOKED");
                return (
                  <li key={entry.seq} className="relative text-sm">
                    <span aria-hidden className={cn("absolute -left-[1.53rem] top-1.5 h-2 w-2 rounded-full ring-4 ring-card", alarming ? "bg-destructive" : "bg-primary/60")} />
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge variant={alarming ? "destructive" : "secondary"}>{entry.action}</Badge>
                      <span className="text-xs text-muted-foreground">{entry.by ?? "system"}</span>
                      <span className="ml-auto font-mono text-[11px] text-muted-foreground">
                        #{entry.seq} · {when(entry.at)}
                      </span>
                    </div>
                  </li>
                );
              })}
            </ol>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Your permissions</CardTitle>
          <CardDescription>Resolved from the role-to-capability map in lib/auth/rbac.ts, which every route checks.</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-2">
          {capabilitiesFor(actor.role).map((capability) => (
            <Badge key={capability} variant="outline" className="font-mono">
              {capability}
            </Badge>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}
