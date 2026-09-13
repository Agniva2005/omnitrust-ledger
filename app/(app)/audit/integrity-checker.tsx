"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

type ChainBreak = { seq: number; entryId: string; problem: string; detail: string };

type CheckpointProblem = { checkpointId: string; seq: number; problem: string; detail: string };

type CheckpointStatus = {
  id: string;
  seq: number;
  createdAt: string;
  trustedTime: string | null;
  timestamp: string;
  valid: boolean;
};

type AuditLogVerification = {
  valid: boolean;
  chain: { valid: boolean; entriesChecked: number; firstBreak?: ChainBreak; breaks: ChainBreak[] };
  checkpoints: CheckpointStatus[];
  problems: CheckpointProblem[];
  latestCheckpoint: CheckpointStatus | null;
  entriesAfterLatestCheckpoint: number;
  explanation: string;
  limitations: string[];
};

export function IntegrityChecker({
  totalEntries,
  canVerify,
  canCheckpoint,
}: {
  totalEntries: number;
  canVerify: boolean;
  canCheckpoint: boolean;
}) {
  const router = useRouter();
  const [result, setResult] = useState<AuditLogVerification | null>(null);
  const [message, setMessage] = useState<{ tone: "error" | "info"; text: string } | null>(null);
  const [pending, setPending] = useState<"verify" | "checkpoint" | null>(null);

  async function verify() {
    setPending("verify");
    setMessage(null);
    setResult(null);
    const response = await fetch("/api/audit/verify", { method: "POST" });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) setMessage({ tone: "error", text: body.error ?? "Integrity check could not be run" });
    else setResult(body.result);
    setPending(null);
    router.refresh();
  }

  async function checkpoint() {
    setPending("checkpoint");
    setMessage(null);
    const response = await fetch("/api/audit/checkpoints", { method: "POST" });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
      setMessage({ tone: "error", text: body.error ?? "The checkpoint could not be created" });
    } else {
      setMessage({
        tone: "info",
        text: `Signed checkpoint created over entries up to sequence ${body.checkpoint.seq}${
          body.checkpoint.timestamped ? ", with a trusted time-stamp" : " (the Time-Stamp Authority was unavailable)"
        }.`,
      });
    }
    setPending(null);
    router.refresh();
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Integrity check</CardTitle>
        <CardDescription>
          Walks all {totalEntries} entries from the genesis hash, then checks every signed checkpoint and
          that the log still hashes to what each one committed to. The chain alone is tamper-
          <em>evident</em> against edits that leave the hashes as they were; checkpoints additionally
          catch a log whose hashes were recomputed after an edit, and entries deleted from the end.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex flex-wrap gap-2">
          {canVerify && (
            <Button onClick={verify} disabled={pending !== null}>
              {pending === "verify" ? "Verifying..." : "Verify log integrity"}
            </Button>
          )}
          {canCheckpoint && (
            <Button variant="outline" onClick={checkpoint} disabled={pending !== null}>
              {pending === "checkpoint" ? "Signing..." : "Create signed checkpoint"}
            </Button>
          )}
        </div>

        {message && (
          <p role={message.tone === "error" ? "alert" : "status"} className={`text-sm ${message.tone === "error" ? "text-destructive" : "text-muted-foreground"}`}>
            {message.text}
          </p>
        )}

        {result && (
          <div className="space-y-3">
            <div className="flex flex-wrap items-center gap-3">
              <Badge variant={result.valid ? "success" : "destructive"}>
                {result.valid ? "LOG VERIFIED" : "TAMPERING DETECTED"}
              </Badge>
              <Badge variant={result.chain.valid ? "secondary" : "destructive"}>
                chain {result.chain.valid ? "intact" : "broken"}
              </Badge>
              <Badge variant={result.problems.length === 0 ? "secondary" : "destructive"}>
                {result.checkpoints.length} checkpoint{result.checkpoints.length === 1 ? "" : "s"}
                {result.problems.length === 0 ? " agree" : ` / ${result.problems.length} problem${result.problems.length === 1 ? "" : "s"}`}
              </Badge>
              <span className="text-sm text-muted-foreground">{result.chain.entriesChecked} entries checked</span>
            </div>

            <p className="max-w-prose rounded-md border p-3 text-sm">{result.explanation}</p>

            {result.chain.firstBreak && (
              <div className="space-y-2 rounded-md border border-destructive/40 bg-destructive/5 p-3 text-sm">
                <div className="font-medium">
                  First chain break at sequence {result.chain.firstBreak.seq} &mdash; {result.chain.firstBreak.problem}
                </div>
                <p className="break-all font-mono text-xs">{result.chain.firstBreak.detail}</p>
                {result.chain.breaks.length > 1 && (
                  <p className="text-xs text-muted-foreground">
                    {result.chain.breaks.length - 1} further break{result.chain.breaks.length - 1 === 1 ? "" : "s"} downstream,
                    as expected once a chain is cut.
                  </p>
                )}
              </div>
            )}

            {result.problems.length > 0 && (
              <ul className="space-y-2">
                {result.problems.map((problem) => (
                  <li key={`${problem.checkpointId}-${problem.problem}`} className="rounded-md border border-destructive/40 bg-destructive/5 p-3 text-sm">
                    <div className="font-medium">
                      Checkpoint at sequence {problem.seq} &mdash; {problem.problem}
                    </div>
                    <p className="break-all font-mono text-xs">{problem.detail}</p>
                  </li>
                ))}
              </ul>
            )}

            <details className="text-sm text-muted-foreground">
              <summary className="cursor-pointer">What this check cannot detect</summary>
              <ul className="mt-2 list-disc space-y-1 pl-5">
                {result.limitations.map((limitation) => (
                  <li key={limitation}>{limitation}</li>
                ))}
              </ul>
            </details>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
