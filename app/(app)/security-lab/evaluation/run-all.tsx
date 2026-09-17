"use client";

import { Loader2, Play } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Button } from "@/components/ui/button";

/**
 * Runs every scenario in turn. Sequential on purpose: each run builds a sandbox of its own and
 * the service refuses a second run while one is in progress, so firing them together would just
 * produce conflicts.
 */
export function RunAll({ scenarioIds }: { scenarioIds: string[] }) {
  const router = useRouter();
  const [running, setRunning] = useState(false);
  const [done, setDone] = useState(0);
  const [current, setCurrent] = useState<string | null>(null);
  const [failed, setFailed] = useState<string[]>([]);

  async function runAll() {
    setRunning(true);
    setDone(0);
    setFailed([]);

    const problems: string[] = [];
    for (const id of scenarioIds) {
      setCurrent(id);
      try {
        const response = await fetch("/api/security-lab", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ scenario: id }),
        });
        if (!response.ok) problems.push(id);
      } catch {
        problems.push(id);
      }
      setDone((count) => count + 1);
    }

    setFailed(problems);
    setCurrent(null);
    setRunning(false);
    router.refresh();
  }

  return (
    <div className="space-y-2">
      <Button onClick={runAll} disabled={running}>
        {running ? <Loader2 aria-hidden className="animate-spin" /> : <Play aria-hidden />}
        {running ? `Running ${done + 1} of ${scenarioIds.length}…` : `Run all ${scenarioIds.length} scenarios`}
      </Button>
      {running && current && (
        <p aria-live="polite" className="font-mono text-xs text-muted-foreground">
          {current}
        </p>
      )}
      {!running && failed.length > 0 && (
        <p role="alert" className="text-xs text-destructive">
          {failed.length} scenario{failed.length === 1 ? "" : "s"} could not be run: {failed.join(", ")}
        </p>
      )}
      <p className="text-xs leading-relaxed text-muted-foreground">
        Each runs in its own throwaway sandbox, one at a time. A full pass takes a couple of minutes and appends one audit
        entry per scenario, which is where the table above reads its results from.
      </p>
    </div>
  );
}
