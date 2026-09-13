"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { EvidenceChain } from "@/components/evidence-chain";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

type StepStatus = "PASS" | "FAIL" | "UNAVAILABLE" | "SKIPPED";

type VerificationStep = {
  id: string;
  step: string;
  status: StepStatus;
  passed: boolean;
  optional?: boolean;
  detail?: string;
};

type Outcome = "VALID" | "INVALID" | "UNVERIFIABLE" | "ERROR";

type TrustSummary = {
  claimedSigningTime: string;
  trustedTime: string | null;
  timestampAccuracyMs: number | null;
  timestampAuthority: string | null;
  certificateEvaluatedAt: string | null;
  certificateExpiredSince: boolean;
  revocation: { reason: string; revokedAt: string; invalidityDate: string | null } | null;
  revocationDecision: string | null;
  policy: string;
};

type VerificationResult = {
  outcome: Outcome;
  reason?: string;
  explanation: string;
  trust: TrustSummary;
  steps: VerificationStep[];
};

const OUTCOME_DISPLAY: Record<
  Outcome,
  { label: string; variant: "success" | "destructive" | "outline"; summary: string }
> = {
  VALID: { label: "AUTHENTIC", variant: "success", summary: "Every required check passed." },
  INVALID: {
    label: "INVALID",
    variant: "destructive",
    summary: "A check found positive evidence that this signed document cannot be trusted.",
  },
  UNVERIFIABLE: {
    label: "UNVERIFIABLE",
    variant: "outline",
    summary:
      "Evidence needed for a decision could not be obtained. This is not a finding that the document was tampered with, and not a finding that it is authentic.",
  },
  ERROR: {
    label: "VERIFICATION ERROR",
    variant: "destructive",
    summary: "The verifier itself failed. The result supports no conclusion either way.",
  },
};

const STEP_STYLE: Record<StepStatus, string> = {
  PASS: "text-success",
  FAIL: "text-destructive",
  UNAVAILABLE: "text-amber-600",
  SKIPPED: "text-muted-foreground",
};

function TrustRow({ label, value }: { label: string; value: string | null }) {
  return (
    <div className="flex flex-wrap gap-x-2">
      <span className="text-muted-foreground">{label}:</span>
      <span className="break-all font-mono text-xs">{value ?? "none"}</span>
    </div>
  );
}

export function VerifyRunner({ documentId }: { documentId: string }) {
  const router = useRouter();
  const [result, setResult] = useState<VerificationResult | null>(null);
  const [notSigned, setNotSigned] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  async function run() {
    setPending(true);
    setError(null);
    setResult(null);
    setNotSigned(false);

    const response = await fetch(`/api/documents/${documentId}/verify`, { method: "POST" });
    const body = await response.json().catch(() => ({}));

    if (response.status === 409 && body.notSigned) {
      setNotSigned(true);
    } else if (!response.ok) {
      setError(body.error ?? "Verification could not be run");
    } else {
      setResult(body.result);
      router.refresh();
    }

    setPending(false);
  }

  const display = result ? OUTCOME_DISPLAY[result.outcome] : null;

  return (
    <Card>
      <CardHeader>
        <CardTitle>Verification workflow</CardTitle>
        <CardDescription>
          Ten steps in order, each with its own result. Certificate validity and revocation are
          judged at the time a trusted time-stamp proves the signature existed.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <Button onClick={run} disabled={pending}>
          {pending ? "Running verification..." : result ? "Run again" : "Run verification"}
        </Button>

        {notSigned && (
          <p className="text-sm text-muted-foreground">
            This document has no signature yet, so there is nothing to verify.
          </p>
        )}

        {error && (
          <p role="alert" className="text-sm text-destructive">
            {error}
          </p>
        )}

        {result && display && (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center gap-3">
              <Badge variant={display.variant}>{display.label}</Badge>
              {result.reason && <span className="font-mono text-sm">{result.reason}</span>}
            </div>

            <p className="max-w-prose text-sm text-muted-foreground">{display.summary}</p>
            <p className="max-w-prose rounded-md border p-3 text-sm">{result.explanation}</p>

            <div className="space-y-1 rounded-md border p-3 text-sm">
              <div className="font-medium">Time and revocation</div>
              <TrustRow label="Trusted time-stamp" value={result.trust.trustedTime} />
              <TrustRow label="Time-Stamp Authority" value={result.trust.timestampAuthority} />
              <TrustRow label="Server clock at signing (not evidence)" value={result.trust.claimedSigningTime} />
              <TrustRow label="Certificate judged at" value={result.trust.certificateEvaluatedAt} />
              <TrustRow
                label="Revocation"
                value={
                  result.trust.revocation
                    ? `${result.trust.revocation.reason} at ${result.trust.revocation.revokedAt}${
                        result.trust.revocation.invalidityDate
                          ? `, invalid from ${result.trust.revocation.invalidityDate}`
                          : ""
                      }`
                    : "not revoked"
                }
              />
              <TrustRow label="Policy decision" value={result.trust.revocationDecision} />
              <TrustRow label="Policy" value={result.trust.policy} />
            </div>

            <EvidenceChain steps={result.steps.filter((step) => !step.id.includes(":"))} />

            <ol className="space-y-2">
              {result.steps.map((step) => (
                <li
                  key={step.id}
                  className={`flex gap-3 rounded-md border px-3 py-2 text-sm ${
                    step.id.startsWith("certificate-validity:") ? "ml-6 border-dashed" : ""
                  }`}
                >
                  <span className={`w-24 shrink-0 font-mono text-xs ${STEP_STYLE[step.status]}`}>
                    {step.status}
                    {step.optional && step.status !== "PASS" ? " (optional)" : ""}
                  </span>
                  <span className="min-w-0">
                    <span className="font-medium">{step.step}</span>
                    {step.detail && (
                      <span className="block break-all font-mono text-xs text-muted-foreground">
                        {step.detail}
                      </span>
                    )}
                  </span>
                </li>
              ))}
            </ol>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
