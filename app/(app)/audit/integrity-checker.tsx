"use client";

import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

type ChainBreak = {
  seq: number;
  entryId: string;
  problem: string;
  detail: string;
};

type IntegrityResult = {
  valid: boolean;
  entriesChecked: number;
  firstBreak?: ChainBreak;
  breaks: ChainBreak[];
  checkedAt: string;
};

export function IntegrityChecker({ totalEntries }: { totalEntries: number }) {
  const [result, setResult] = useState<IntegrityResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  async function run() {
    setPending(true);
    setError(null);
    setResult(null);

    const response = await fetch("/api/audit/verify", { method: "POST" });
    const body = await response.json().catch(() => ({}));

    if (!response.ok) setError(body.error ?? "Integrity check could not be run");
    else setResult(body.result);

    setPending(false);
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Integrity check</CardTitle>
        <CardDescription>
          Walks all {totalEntries} entries from the genesis hash, recomputing each entry hash from
          its own fields and its predecessor&apos;s hash. This makes the log tamper-<em>evident</em>,
          not tamper-proof: someone with database access can still alter a row, and this check is
          what surfaces that they did.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <Button onClick={run} disabled={pending}>
          {pending ? "Walking the chain..." : "Verify log integrity"}
        </Button>

        {error && (
          <p role="alert" className="text-sm text-destructive">
            {error}
          </p>
        )}

        {result && (
          <div className="space-y-3">
            <div className="flex flex-wrap items-center gap-3">
              <Badge variant={result.valid ? "success" : "destructive"}>
                {result.valid ? "CHAIN INTACT" : "CHAIN BROKEN"}
              </Badge>
              <span className="text-sm text-muted-foreground">
                {result.entriesChecked} entries checked
              </span>
            </div>

            {result.firstBreak && (
              <div className="space-y-2 rounded-md border border-destructive/40 bg-destructive/5 p-3 text-sm">
                <div className="font-medium">
                  First break at sequence {result.firstBreak.seq} &mdash;{" "}
                  {result.firstBreak.problem}
                </div>
                <p className="break-all font-mono text-xs">{result.firstBreak.detail}</p>
                {result.breaks.length > 1 && (
                  <p className="text-xs text-muted-foreground">
                    {result.breaks.length - 1} further break
                    {result.breaks.length - 1 === 1 ? "" : "s"} downstream, as expected once a
                    chain is cut.
                  </p>
                )}
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
