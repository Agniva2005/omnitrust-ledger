"use client";

import { Loader2, Play, Square } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export type NodeStatus = { reachable: boolean; rpcUrl: string; startedByApp: number | null };

export function ChainControl({ initial }: { initial: NodeStatus }) {
  const router = useRouter();
  const [node, setNode] = useState(initial);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState<"start" | "stop" | null>(null);

  async function run(action: "start" | "stop") {
    setPending(action);
    setError(null);

    const response = await fetch("/api/anchoring/node", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action }),
    });
    const payload = await response.json().catch(() => ({}));

    if (!response.ok) {
      setError(payload.error ?? "That could not be done");
      setPending(null);
      return;
    }

    setNode(payload.node);
    setPending(null);
    router.refresh();
  }

  return (
    <div className="space-y-3">
      <div
        className={cn(
          "rounded-lg border p-3 text-sm",
          node.reachable ? "border-success/35 bg-success/[0.07] text-success" : "border-warning/40 bg-warning/[0.07] text-warning",
        )}
      >
        {node.reachable ? (
          <>A chain is answering at <span className="font-mono text-xs">{node.rpcUrl}</span>.</>
        ) : (
          <>Nothing is answering at <span className="font-mono text-xs">{node.rpcUrl}</span>, so anchors cannot be recorded or checked.</>
        )}
      </div>

      {error && <p role="alert" className="rounded-lg border border-destructive/35 bg-destructive/[0.07] px-3 py-2 text-sm text-destructive">{error}</p>}

      <div className="flex flex-wrap gap-2">
        <Button type="button" size="sm" disabled={pending !== null || node.reachable} onClick={() => run("start")}>
          {pending === "start" ? <Loader2 aria-hidden className="animate-spin" /> : <Play aria-hidden />}
          {pending === "start" ? "Starting the chain…" : "Start the local chain"}
        </Button>
        <Button
          type="button"
          size="sm"
          variant="secondary"
          disabled={pending !== null || node.startedByApp === null}
          onClick={() => run("stop")}
        >
          {pending === "stop" ? <Loader2 aria-hidden className="animate-spin" /> : <Square aria-hidden />}
          Stop it
        </Button>
      </div>

      <p className="text-xs leading-relaxed text-muted-foreground">
        This runs the same local development chain as <span className="font-mono">npm run chain</span>, in its own process.
        Stopping is offered only for a chain this application started. A restarted chain is a new chain: anchors recorded on
        the previous one will report that their root is not there, which is the honest answer rather than a failure.
      </p>
    </div>
  );
}
