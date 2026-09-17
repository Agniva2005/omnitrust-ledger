import { ArrowLeft, ClipboardCheck, Download } from "lucide-react";
import Link from "next/link";
import { redirect } from "next/navigation";
import { RunAll } from "@/app/(app)/security-lab/evaluation/run-all";
import { PageHeader } from "@/components/page-header";
import { Badge } from "@/components/ui/badge";
import { Button, buttonVariants } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { can } from "@/lib/auth/rbac";
import { getSession } from "@/lib/auth/session";
import { buildEvaluation, type ScenarioOutcome } from "@/lib/security-lab/evaluation";
import { cn } from "@/lib/utils";

export const dynamic = "force-dynamic";

const OUTCOME: Record<ScenarioOutcome, { label: string; variant: "success" | "destructive" | "warning" }> = {
  HELD: { label: "HELD", variant: "success" },
  FAILED: { label: "FAILED", variant: "destructive" },
  ERROR: { label: "ERROR", variant: "warning" },
};

function Stat({ label, value, tone }: { label: string; value: number; tone?: string }) {
  return (
    <div className="rounded-xl border bg-card px-4 py-3 shadow-card">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className={cn("mt-1 text-2xl font-semibold tabular-nums", tone)}>{value}</div>
    </div>
  );
}

export default async function EvaluationPage() {
  const actor = await getSession();
  if (!actor) redirect("/login");
  if (!can(actor.role, "lab:run")) redirect("/security-lab");

  const evaluation = await buildEvaluation(actor);
  const { totals, coverage } = evaluation;

  return (
    <div className="space-y-6">
      <PageHeader
        icon={ClipboardCheck}
        eyebrow="Evaluation"
        title="Adversarial evaluation"
        description="Every attack scenario, the adversary capability it exercises, the control meant to stop it, and the result of the most recent real run. Results are read back out of the hash-chained audit log rather than kept separately, so the evaluation is protected by the same mechanism it is evaluating: each row names the audit entry it came from."
        actions={
          <div className="flex flex-wrap gap-2">
            <a className={cn(buttonVariants({ variant: "outline" }))} href="/api/security-lab/evaluation">
              <Download aria-hidden /> Evidence pack
            </a>
            <Button asChild variant="outline">
              <Link href="/security-lab">
                <ArrowLeft aria-hidden /> Security Lab
              </Link>
            </Button>
          </div>
        }
      />

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
        <Stat label="Scenarios" value={totals.scenarios} />
        <Stat label="Controls held" value={totals.held} tone="text-success" />
        <Stat label="Controls failed" value={totals.failed} tone={totals.failed ? "text-destructive" : undefined} />
        <Stat label="Errored" value={totals.errored} tone={totals.errored ? "text-warning" : undefined} />
        <Stat label="Never run here" value={totals.neverRun} tone={totals.neverRun ? "text-muted-foreground" : undefined} />
      </div>

      <div
        className={cn(
          "rounded-xl border p-4 text-sm",
          evaluation.productionTouched === 0 ? "border-success/35 bg-success/[0.07] text-success" : "border-destructive/35 bg-destructive/[0.07] text-destructive",
        )}
      >
        {evaluation.productionTouched === 0
          ? "Every recorded run reported this installation's own records unchanged: same counts and same audit head before and after."
          : `${evaluation.productionTouched} run(s) reported this installation's records as changed, which should never happen.`}
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Coverage by adversary capability</CardTitle>
          <CardDescription>
            The threat model names the capabilities this installation claims to defend against. A capability is only
            demonstrated when every scenario exercising it has actually been run here and its control held.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-2">
          {coverage.map((row) => (
            <div key={row.adversary} className="flex flex-wrap items-center gap-x-3 gap-y-1 rounded-lg border p-3">
              <Badge variant={row.fullyDemonstrated ? "success" : "secondary"}>{row.fullyDemonstrated ? "demonstrated" : "not yet"}</Badge>
              <span className="text-sm font-medium">{row.label}</span>
              <span className="font-mono text-xs text-muted-foreground">
                {row.held}/{row.scenarios} held · {row.run} run
              </span>
              <span className="w-full text-xs leading-relaxed text-muted-foreground">{row.capability}</span>
            </div>
          ))}
        </CardContent>
      </Card>

      <Card className="overflow-hidden">
        <CardHeader>
          <CardTitle>Every scenario</CardTitle>
          <CardDescription>
            A scenario that has never been run here says so rather than being counted as a pass. The audit column is the
            entry the result was read from; the Audit log page will walk the chain that protects it.
          </CardDescription>
        </CardHeader>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="pl-5">Scenario</TableHead>
              <TableHead>Adversary</TableHead>
              <TableHead>Property</TableHead>
              <TableHead>Holds if</TableHead>
              <TableHead>Latest result</TableHead>
              <TableHead className="pr-5">Audit</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {evaluation.rows.map(({ scenario, adversaryLabel, latest, runCount }) => (
              <TableRow key={scenario.id}>
                <TableCell className="pl-5 align-top">
                  <div className="text-sm font-medium">{scenario.title}</div>
                  <div className="mt-0.5 max-w-md text-xs leading-relaxed text-muted-foreground">{scenario.attack}</div>
                </TableCell>
                <TableCell className="align-top text-xs">{adversaryLabel}</TableCell>
                <TableCell className="align-top text-xs">{scenario.property}</TableCell>
                <TableCell className="align-top font-mono text-[11px]">{scenario.expected}</TableCell>
                <TableCell className="align-top">
                  {latest ? (
                    <div className="space-y-1">
                      <Badge variant={OUTCOME[latest.outcome].variant}>{OUTCOME[latest.outcome].label}</Badge>
                      <div className="font-mono text-[10px] text-muted-foreground">
                        {latest.at.replace("T", " ").slice(0, 19)}Z{latest.durationMs === null ? "" : ` · ${latest.durationMs} ms`}
                      </div>
                      {latest.subjectFilename && <div className="text-[10px] text-muted-foreground">on {latest.subjectFilename}</div>}
                      {runCount > 1 && <div className="text-[10px] text-muted-foreground">{runCount} runs recorded</div>}
                    </div>
                  ) : (
                    <span className="text-xs text-muted-foreground">never run here</span>
                  )}
                </TableCell>
                <TableCell className="pr-5 align-top font-mono text-[10px] text-muted-foreground">
                  {latest ? (
                    <>
                      #{latest.auditSeq}
                      <div className="[overflow-wrap:anywhere]">{latest.auditHash.slice(0, 16)}…</div>
                    </>
                  ) : (
                    "—"
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Run the whole suite</CardTitle>
          <CardDescription>Fills in every row above with a real run, so the table reflects this machine rather than a previous one.</CardDescription>
        </CardHeader>
        <CardContent>
          <RunAll scenarioIds={evaluation.rows.map((row) => row.scenario.id)} />
        </CardContent>
      </Card>
    </div>
  );
}
