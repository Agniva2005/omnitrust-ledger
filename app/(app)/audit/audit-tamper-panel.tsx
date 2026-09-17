"use client";

import { FlaskConical, Loader2, RotateCcw, ShieldAlert } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";

type Action = "edit" | "delete" | "rewrite" | "restore";

export type AuditTamperState = { altered: boolean; snapshotRows: number };

const ATTACKS: { action: Action; label: string; blurb: string }[] = [
  {
    action: "edit",
    label: "Edit this entry",
    blurb: "Changes its metadata and leaves every stored hash alone. The chain should fail at exactly this sequence number.",
  },
  {
    action: "delete",
    label: "Delete this entry",
    blurb: "Removes the row completely, which shows up as a gap in the sequence rather than a bad hash.",
  },
  {
    action: "rewrite",
    label: "Edit it and recompute every later hash",
    blurb: "The attack a plain hash chain cannot survive: the chain is made internally consistent again, so only a checkpoint made beforehand still disagrees.",
  },
];

export function AuditTamperPanel({ initialState, maxSeq }: { initialState: AuditTamperState; maxSeq: number }) {
  const router = useRouter();
  const [state, setState] = useState(initialState);
  const [seq, setSeq] = useState<string>(maxSeq > 2 ? String(Math.ceil(maxSeq / 2)) : "1");
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState<Action | null>(null);

  async function run(action: Action) {
    setPending(action);
    setError(null);

    const response = await fetch("/api/audit/demo-tamper", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(action === "restore" ? { action } : { action, seq: Number(seq) }),
    });
    const payload = await response.json().catch(() => ({}));

    if (!response.ok) {
      setError(payload.error ?? "That could not be done");
      setPending(null);
      return;
    }

    setState(payload.state);
    setPending(null);
    router.refresh();
  }

  return (
    <Card className="border-dashed">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <FlaskConical aria-hidden className="h-4 w-4 text-primary" /> Tamper with this log
        </CardTitle>
        <CardDescription>
          Demonstration only, ADMIN alone. These edit the real audit log, not a copy, so the integrity check above is
          reporting on rows that genuinely changed. Every altered row is kept first, so Restore puts the log back exactly
          as it was — including an entry deleted outright.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div
          className={cn(
            "rounded-lg border p-3 text-sm",
            state.altered ? "border-destructive/35 bg-destructive/[0.07] text-destructive" : "border-success/35 bg-success/[0.07] text-success",
          )}
        >
          {state.altered ? `The log has been altered. ${state.snapshotRows} original rows are kept for Restore.` : "The log is as the application wrote it."}
        </div>

        {error && <p role="alert" className="rounded-lg border border-destructive/35 bg-destructive/[0.07] px-3 py-2 text-sm text-destructive">{error}</p>}

        <div className="space-y-1.5">
          <label htmlFor="tamper-seq" className="text-sm font-medium">
            Entry to attack
          </label>
          <input
            id="tamper-seq"
            type="number"
            min={1}
            max={maxSeq}
            value={seq}
            onChange={(event) => setSeq(event.target.value)}
            className="w-32 rounded-lg border border-input bg-background px-3 py-1.5 font-mono text-sm focus-visible:ring-2 focus-visible:ring-ring"
          />
          <p className="text-xs text-muted-foreground">Sequence number, 1 to {maxSeq}. Pick one in the middle so the break has entries after it.</p>
        </div>

        <div className="space-y-2">
          {ATTACKS.map((attack) => (
            <div key={attack.action} className="rounded-lg border p-3">
              <Button type="button" variant="secondary" size="sm" disabled={pending !== null} onClick={() => run(attack.action)}>
                {pending === attack.action ? <Loader2 aria-hidden className="animate-spin" /> : <ShieldAlert aria-hidden />}
                {attack.label}
              </Button>
              <p className="mt-2 text-xs leading-relaxed text-muted-foreground">{attack.blurb}</p>
            </div>
          ))}
        </div>

        <Button type="button" size="sm" disabled={pending !== null || !state.altered} onClick={() => run("restore")}>
          {pending === "restore" ? <Loader2 aria-hidden className="animate-spin" /> : <RotateCcw aria-hidden />}
          Restore the log
        </Button>
      </CardContent>
    </Card>
  );
}
