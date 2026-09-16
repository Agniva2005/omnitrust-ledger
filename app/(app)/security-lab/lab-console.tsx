"use client";

import { CircleAlert, CircleCheck, CircleX, FlaskConical, Loader2, Play, RotateCcw } from "lucide-react";
import { useMemo, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { adversaryFor, type ScenarioDefinition, type ScenarioResult } from "@/lib/security-lab/catalog";
import { cn } from "@/lib/utils";

type Run = {
  result: ScenarioResult;
  runId: string;
  durationMs: number;
  sandboxRemoved: boolean;
  subject: { filename: string; byteLength: number } | null;
  production: { untouched: boolean; before: Record<string, unknown>; after: Record<string, unknown> };
};

export type SubjectOption = { id: string; filename: string };

const OUTCOME_STYLE: Record<ScenarioResult["outcome"], { label: string; variant: "success" | "destructive" | "warning"; tone: string; icon: typeof CircleCheck }> = {
  HELD: { label: "CONTROL HELD", variant: "success", tone: "border-success/35 bg-success/[0.06]", icon: CircleCheck },
  FAILED: { label: "CONTROL FAILED", variant: "destructive", tone: "border-destructive/35 bg-destructive/[0.06]", icon: CircleX },
  // A scenario that could not complete proves nothing either way: a warning, not a pass or a failure.
  ERROR: { label: "SCENARIO ERROR", variant: "warning", tone: "border-warning/40 bg-warning/[0.07]", icon: CircleAlert },
};

export function LabConsole({
  scenarios,
  canRun = true,
  documents = [],
}: {
  scenarios: readonly ScenarioDefinition[];
  canRun?: boolean;
  documents?: readonly SubjectOption[];
}) {
  const [runs, setRuns] = useState<Record<string, Run>>({});
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const [category, setCategory] = useState<string>("all");
  const [subjectId, setSubjectId] = useState<string>("");

  const subjectCount = scenarios.filter((scenario) => scenario.acceptsSubject).length;

  const categories = useMemo(() => ["all", ...Array.from(new Set(scenarios.map((scenario) => scenario.category)))], [scenarios]);
  const visible = category === "all" ? scenarios : scenarios.filter((scenario) => scenario.category === category);
  const outcomes = Object.values(runs).map((run) => run.result.outcome);
  const held = outcomes.filter((outcome) => outcome === "HELD").length;
  const failed = outcomes.filter((outcome) => outcome === "FAILED").length;
  const errored = outcomes.filter((outcome) => outcome === "ERROR").length;

  async function run(id: string) {
    setBusy(id);
    setErrors((current) => ({ ...current, [id]: "" }));
    // A chosen document is sent only to the scenarios whose subject is a document; the rest
    // attack the log or the login and would reject it.
    const usesSubject = subjectId !== "" && scenarios.find((scenario) => scenario.id === id)?.acceptsSubject;
    const response = await fetch("/api/security-lab", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(usesSubject ? { scenario: id, documentId: subjectId } : { scenario: id }),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) setErrors((current) => ({ ...current, [id]: body.error ?? "The scenario could not be run" }));
    else setRuns((current) => ({ ...current, [id]: body.run }));
    setBusy(null);
  }

  return (
    <div className="space-y-5">
      <div className="grid gap-3 sm:grid-cols-4">
        {[
          { label: "Scenarios", value: scenarios.length, className: "" },
          { label: "Held this session", value: held, className: "text-success" },
          { label: "Failed this session", value: failed, className: failed ? "text-destructive" : "" },
          { label: "Errored this session", value: errored, className: errored ? "text-warning" : "" },
        ].map((stat) => (
          <div key={stat.label} className="rounded-xl border bg-card px-4 py-3 shadow-card">
            <div className="text-xs text-muted-foreground">{stat.label}</div>
            <div className={cn("mt-1 text-2xl font-semibold tabular-nums", stat.className)}>{stat.value}</div>
          </div>
        ))}
      </div>

      {canRun && documents.length > 0 && (
        <div className="rounded-xl border bg-card p-4 shadow-card">
          <label htmlFor="lab-subject" className="text-sm font-medium">
            Subject document
          </label>
          <p className="mt-1 text-xs text-muted-foreground">
            The {subjectCount} scenarios whose subject is a document can attack one of yours instead of content the sandbox
            invents. The sandbox keeps its own database, storage and master key, and cannot read this application&apos;s
            encrypted blobs; a plaintext copy of the document you pick is placed in the run directory and deleted with it.
            Nothing is written back.
          </p>
          <select
            id="lab-subject"
            value={subjectId}
            onChange={(event) => setSubjectId(event.target.value)}
            className="mt-3 w-full max-w-lg rounded-lg border border-input bg-background px-3 py-2 text-sm focus-visible:ring-2 focus-visible:ring-ring"
          >
            <option value="">The sandbox&apos;s own invented content</option>
            {documents.map((document) => (
              <option key={document.id} value={document.id}>
                {document.filename}
              </option>
            ))}
          </select>
        </div>
      )}

      <div role="group" aria-label="Filter scenarios by category" className="flex flex-wrap gap-1.5">
        {categories.map((name) => (
          <button
            key={name}
            type="button"
            aria-pressed={category === name}
            onClick={() => setCategory(name)}
            className={cn(
              "rounded-full border px-3 py-1 text-xs capitalize transition-colors focus-visible:ring-2 focus-visible:ring-ring",
              category === name ? "border-primary/50 bg-accent text-accent-foreground" : "bg-card text-muted-foreground hover:text-foreground",
            )}
          >
            {name === "all" ? `All (${scenarios.length})` : `${name} (${scenarios.filter((scenario) => scenario.category === name).length})`}
          </button>
        ))}
      </div>

      <div className="grid gap-4 lg:grid-cols-2 3xl:grid-cols-3">
        {visible.map((scenario) => {
          const result = runs[scenario.id];
          const style = result ? OUTCOME_STYLE[result.result.outcome] : null;
          return (
            <Card key={scenario.id} className="flex flex-col">
              <CardHeader>
                <div className="flex items-start justify-between gap-2">
                  <CardTitle className="flex items-start gap-2">
                    <FlaskConical aria-hidden className="mt-0.5 h-4 w-4 shrink-0 text-primary" />
                    {scenario.title}
                  </CardTitle>
                  <Badge variant="secondary">{scenario.category}</Badge>
                </div>
                <CardDescription>{scenario.attack}</CardDescription>
              </CardHeader>
              <CardContent className="flex flex-1 flex-col gap-3 text-sm">
                <dl className="space-y-2 rounded-lg border bg-muted/25 p-3">
                  <div>
                    <dt className="inline text-muted-foreground">Adversary: </dt>
                    <dd className="inline" title={adversaryFor(scenario.adversary).capability}>
                      {adversaryFor(scenario.adversary).label}
                      <span className="text-muted-foreground"> · attacks {scenario.property}</span>
                    </dd>
                  </div>
                  <div>
                    <dt className="inline text-muted-foreground">Control: </dt>
                    <dd className="inline">{scenario.defence}</dd>
                  </div>
                  <div>
                    <dt className="inline text-muted-foreground">Holds if: </dt>
                    <dd className="inline font-mono text-xs">{scenario.expected}</dd>
                  </div>
                  {subjectId !== "" && (
                    <div>
                      <dt className="inline text-muted-foreground">Subject: </dt>
                      <dd className="inline">
                        {scenario.acceptsSubject ? (
                          documents.find((document) => document.id === subjectId)?.filename
                        ) : (
                          <span className="text-muted-foreground">not a document scenario; uses the sandbox&apos;s own content</span>
                        )}
                      </dd>
                    </div>
                  )}
                </dl>
                <div hidden={!canRun}>
                  <Button size="sm" onClick={() => run(scenario.id)} disabled={busy !== null || !canRun}>
                    {busy === scenario.id ? <Loader2 aria-hidden className="animate-spin" /> : result ? <RotateCcw aria-hidden /> : <Play aria-hidden />}
                    {busy === scenario.id ? "Running in sandbox..." : result ? "Run again" : "Run attack"}
                  </Button>
                </div>
                {errors[scenario.id] && (
                  <p role="alert" className="rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2 text-destructive">
                    {errors[scenario.id]}
                  </p>
                )}
                {result && style && (
                  <div role="status" className={cn("animate-slide-up space-y-2 rounded-lg border p-3", style.tone)}>
                    <div className="flex flex-wrap items-center gap-2">
                      <style.icon aria-hidden className="h-4 w-4" />
                      <Badge variant={style.variant}>{style.label}</Badge>
                      <span className="text-xs text-muted-foreground">{result.durationMs} ms</span>
                    </div>
                    <p>{result.result.observed}</p>
                    {result.subject && (
                      <p className="text-xs text-muted-foreground">
                        Subject: {result.subject.filename} ({result.subject.byteLength.toLocaleString()} bytes from this installation)
                      </p>
                    )}
                    {result.result.steps.length > 0 && (
                      <ol className="list-decimal space-y-1 pl-5 text-xs text-muted-foreground">
                        {result.result.steps.map((step) => (
                          <li key={step}>{step}</li>
                        ))}
                      </ol>
                    )}
                    <p className="text-xs text-muted-foreground">
                      Sandbox {result.runId} {result.sandboxRemoved ? "deleted after the run" : "NOT deleted"}; application
                      database {result.production.untouched ? "unchanged (record counts and audit head identical before and after)" : "CHANGED during the run"}.
                    </p>
                  </div>
                )}
              </CardContent>
            </Card>
          );
        })}
      </div>
    </div>
  );
}
