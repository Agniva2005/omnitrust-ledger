import Link from "next/link";
import { redirect } from "next/navigation";
import { DistributionBars } from "@/components/distribution-bar";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { VerdictBadge } from "@/components/verdict-badge";
import { capabilitiesFor } from "@/lib/auth/rbac";
import { getSession } from "@/lib/auth/session";
import { systemOverview } from "@/lib/dashboard/overview";

export const dynamic = "force-dynamic";

function Stat({ label, value, detail, href }: { label: string; value: string | number; detail?: string; href?: string }) {
  const body = (
    <Card className="h-full transition-colors hover:border-foreground/20">
      <CardHeader className="pb-2">
        <CardDescription>{label}</CardDescription>
        <CardTitle className="text-3xl tabular-nums">{value}</CardTitle>
      </CardHeader>
      {detail && <CardContent className="pt-0 text-xs text-muted-foreground">{detail}</CardContent>}
    </Card>
  );
  return href ? <Link href={href}>{body}</Link> : body;
}

function when(iso: string) {
  return iso.replace("T", " ").slice(0, 19);
}

export default async function DashboardPage() {
  const actor = await getSession();
  if (!actor) redirect("/login");

  const overview = await systemOverview(actor);
  const { trustServices, integrity } = overview;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Dashboard</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Signed in as {actor.email} ({actor.role}). Every figure below is read from the database for this request.
        </p>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Stat label="Documents" value={overview.documents.total} href="/documents" />
        <Stat
          label="Signatures"
          value={overview.signatures.total}
          detail={`${overview.signatures.timestamped} time-stamped, ${overview.signatures.withCms} with a CMS export`}
          href="/documents"
        />
        <Stat
          label="Certificates"
          value={overview.certificates.total}
          detail={overview.certificates.byStatus.map((row) => `${row.count} ${row.key.toLowerCase()}`).join(", ") || "none issued"}
          href="/certificates"
        />
        <Stat
          label="Audit entries"
          value={integrity.auditEntries}
          detail={
            integrity.latestCheckpoint
              ? `${integrity.checkpoints} signed checkpoint${integrity.checkpoints === 1 ? "" : "s"}; ${integrity.entriesAfterLatestCheckpoint} entries since the latest`
              : "no signed checkpoint yet"
          }
          href="/audit"
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Documents by lifecycle state</CardTitle>
          </CardHeader>
          <CardContent>
            <DistributionBars rows={overview.documents.byStatus} empty="No documents yet." />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Signatures by algorithm</CardTitle>
            <CardDescription>
              <Link href="/algorithms" className="underline underline-offset-2">
                Compare algorithms
              </Link>
            </CardDescription>
          </CardHeader>
          <CardContent>
            <DistributionBars rows={overview.signatures.byAlgorithm} empty="No signatures yet." />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Trust services</CardTitle>
            <CardDescription>Local and demo-grade; trusted by nothing outside this installation.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            <div>
              <div className="font-medium">Root CA</div>
              <div className="text-xs text-muted-foreground">
                {trustServices.ca ? `${trustServices.ca.algorithm}, valid until ${trustServices.ca.notAfter.slice(0, 10)}` : "not created"}
              </div>
            </div>
            <div>
              <div className="font-medium">Time-Stamp Authority</div>
              <div className="text-xs text-muted-foreground">
                {trustServices.tsa ? `${trustServices.tsa.algorithm}, RFC 3161, valid until ${trustServices.tsa.expiresAt.slice(0, 10)}` : "created on first time-stamp"}
              </div>
            </div>
            <div>
              <div className="font-medium">Latest issued CRL</div>
              <div className="text-xs text-muted-foreground">
                {trustServices.latestCrl
                  ? `#${trustServices.latestCrl.crlNumber}, issued ${when(trustServices.latestCrl.thisUpdate)}, ${trustServices.latestCrl.withinValidity ? "within its validity" : "past its next update"}`
                  : "none issued yet"}
              </div>
            </div>
            <div>
              <div className="font-medium">Anchoring</div>
              <div className="text-xs text-muted-foreground">
                {integrity.anchorBatches} batch{integrity.anchorBatches === 1 ? "" : "es"} covering {integrity.anchoredItems} item{integrity.anchoredItems === 1 ? "" : "s"} recorded.{" "}
                <Link href="/anchoring" className="underline underline-offset-2">
                  Whether the chain that holds them is still running
                </Link>{" "}
                decides if they can be checked.
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Recent verifications</CardTitle>
            <CardDescription>From the audit log. VALID, INVALID, UNVERIFIABLE and ERROR are kept distinct.</CardDescription>
          </CardHeader>
          <CardContent>
            {overview.recentVerifications.length === 0 ? (
              <p className="text-sm text-muted-foreground">No verifications have been run yet.</p>
            ) : (
              <ul className="divide-y">
                {overview.recentVerifications.map((entry) => (
                  <li key={entry.seq} className="flex flex-wrap items-center gap-x-3 gap-y-1 py-2 text-sm">
                    <VerdictBadge outcome={entry.outcome} />
                    <Link href={`/documents/${entry.documentId}`} className="font-medium hover:underline">
                      {entry.filename}
                    </Link>
                    {entry.reason && <span className="font-mono text-xs text-muted-foreground">{entry.reason}</span>}
                    <span className="ml-auto text-xs text-muted-foreground">{when(entry.at)}</span>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Recent activity</CardTitle>
            <CardDescription>
              The newest entries of the hash-chained audit log.{" "}
              <Link href="/audit" className="underline underline-offset-2">
                Full timeline
              </Link>
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ul className="divide-y">
              {overview.recentActivity.map((entry) => (
                <li key={entry.seq} className="flex flex-wrap items-center gap-x-3 gap-y-1 py-2 text-sm">
                  <span className="w-10 font-mono text-xs text-muted-foreground">#{entry.seq}</span>
                  <Badge variant={entry.action.includes("FAILED") || entry.action.includes("REVOKED") ? "destructive" : "secondary"}>
                    {entry.action}
                  </Badge>
                  <span className="text-xs text-muted-foreground">{entry.by ?? "system"}</span>
                  <span className="ml-auto text-xs text-muted-foreground">{when(entry.at)}</span>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Your permissions</CardTitle>
          <CardDescription>Resolved from the role-to-capability map in lib/auth/rbac.ts, which every route checks.</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-2">
          {capabilitiesFor(actor.role).map((capability) => (
            <Badge key={capability} variant="secondary">
              {capability}
            </Badge>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}
