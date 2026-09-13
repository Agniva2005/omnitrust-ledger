"use client";

import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import type { ScenarioDefinition, ScenarioResult } from "@/lib/security-lab/catalog";

type Run = {
  result: ScenarioResult;
  runId: string;
  durationMs: number;
  sandboxRemoved: boolean;
  production: { untouched: boolean; before: Record<string, unknown>; after: Record<string, unknown> };
};

const OUTCOME_STYLE: Record<ScenarioResult["outcome"], { label: string; variant: "success" | "destructive" | "outline" }> = {
  HELD: { label: "CONTROL HELD", variant: "success" },
  FAILED: { label: "CONTROL FAILED", variant: "destructive" },
  ERROR: { label: "SCENARIO ERROR", variant: "outline" },
};

export function LabConsole({ scenarios }: { scenarios: readonly ScenarioDefinition[] }) {
  const [runs, setRuns] = useState<Record<string, Run>>({});
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState<string | null>(null);

  async function run(id: string) {
    setBusy(id);
    setErrors((current) => ({ ...current, [id]: "" }));
    const response = await fetch("/api/security-lab", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scenario: id }),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) setErrors((current) => ({ ...current, [id]: body.error ?? "The scenario could not be run" }));
    else setRuns((current) => ({ ...current, [id]: body.run }));
    setBusy(null);
  }

  return (
    <div className="grid gap-4 lg:grid-cols-2">
      {scenarios.map((scenario) => {
        const result = runs[scenario.id];
        return (
          <Card key={scenario.id}>
            <CardHeader>
              <div className="flex items-center justify-between gap-2">
                <CardTitle className="text-base">{scenario.title}</CardTitle>
                <Badge variant="secondary">{scenario.category}</Badge>
              </div>
              <CardDescription>{scenario.attack}</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3 text-sm">
              <div>
                <span className="text-muted-foreground">Control: </span>
                {scenario.defence}
              </div>
              <div>
                <span className="text-muted-foreground">Holds if: </span>
                <span className="font-mono text-xs">{scenario.expected}</span>
              </div>
              <Button size="sm" onClick={() => run(scenario.id)} disabled={busy !== null}>
                {busy === scenario.id ? "Running in sandbox..." : result ? "Run again" : "Run attack"}
              </Button>
              {errors[scenario.id] && (
                <p role="alert" className="text-destructive">
                  {errors[scenario.id]}
                </p>
              )}
              {result && (
                <div className="space-y-2 rounded-md border p-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge variant={OUTCOME_STYLE[result.result.outcome].variant}>{OUTCOME_STYLE[result.result.outcome].label}</Badge>
                    <span className="text-xs text-muted-foreground">{result.durationMs} ms</span>
                  </div>
                  <p>{result.result.observed}</p>
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
  );
}
