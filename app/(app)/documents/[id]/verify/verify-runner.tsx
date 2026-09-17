"use client";

import { CircleAlert, CircleCheck, CircleHelp, CircleX, Loader2, Minus, Package, Play, RotateCcw } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { EvidenceChain } from "@/components/evidence-chain";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";

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

const OUTCOME_DISPLAY: Record<Outcome, { label: string; summary: string; tone: string; icon: typeof CircleCheck }> = {
  VALID: {
    label: "AUTHENTIC",
    summary: "Every required check passed.",
    tone: "border-success/35 bg-success/[0.07] text-success",
    icon: CircleCheck,
  },
  INVALID: {
    label: "INVALID",
    summary: "A check found positive evidence that this signed document cannot be trusted.",
    tone: "border-destructive/35 bg-destructive/[0.07] text-destructive",
    icon: CircleX,
  },
  UNVERIFIABLE: {
    label: "UNVERIFIABLE",
    summary:
      "Evidence needed for a decision could not be obtained. This is not a finding that the document was tampered with, and not a finding that it is authentic.",
    tone: "border-warning/40 bg-warning/[0.08] text-warning",
    icon: CircleHelp,
  },
  ERROR: {
    label: "VERIFICATION ERROR",
    summary: "The verifier itself failed. The result supports no conclusion either way.",
    tone: "border-destructive/35 bg-destructive/[0.07] text-destructive",
    icon: CircleAlert,
  },
};

const STEP_DISPLAY: Record<StepStatus, { icon: typeof CircleCheck; className: string }> = {
  PASS: { icon: CircleCheck, className: "text-success" },
  FAIL: { icon: CircleX, className: "text-destructive" },
  UNAVAILABLE: { icon: CircleHelp, className: "text-warning" },
  SKIPPED: { icon: Minus, className: "text-muted-foreground" },
};

function TrustRow({ label, value }: { label: string; value: string | null }) {
  return (
    <div className="min-w-0 space-y-0.5">
      <dt className="text-xs text-muted-foreground">{label}:</dt>
      <dd className="font-mono text-xs [overflow-wrap:anywhere]">{value ?? "none"}</dd>
    </div>
  );
}

export type VerificationMoment = { id: string; label: string; at: string; detail: string };

export function VerifyRunner({
  documentId,
  version,
  moments = [],
}: {
  documentId: string;
  version?: number;
  moments?: VerificationMoment[];
}) {
  const router = useRouter();
  const [result, setResult] = useState<VerificationResult | null>(null);
  const [notSigned, setNotSigned] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  // null means the present: the verifier's own default rather than a chosen instant.
  const [at, setAt] = useState<string | null>(null);

  async function run(instant: string | null = at) {
    setPending(true);
    setError(null);
    setResult(null);
    setNotSigned(false);

    const response = await fetch(`/api/documents/${documentId}/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ...(version === undefined ? {} : { version }),
        ...(instant === null ? {} : { at: instant }),
      }),
    });
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
      <CardHeader className="flex-row flex-wrap items-start justify-between gap-4 space-y-0">
        <div className="space-y-1">
          <CardTitle>Verification workflow</CardTitle>
          <CardDescription>
            Ten steps in order, each with its own result. Certificate validity and revocation are
            judged at the time a trusted time-stamp proves the signature existed.
          </CardDescription>
        </div>
        <Button onClick={() => run()} disabled={pending} size="lg">
          {pending ? <Loader2 aria-hidden className="animate-spin" /> : result ? <RotateCcw aria-hidden /> : <Play aria-hidden />}
          {pending ? "Running verification..." : result ? "Run again" : "Run verification"}
        </Button>
      </CardHeader>
      <CardContent className="space-y-5">
        {moments.length > 0 && (
          <div className="rounded-xl border bg-muted/20 p-4">
            <div className="flex flex-wrap items-baseline justify-between gap-2">
              <h3 className="text-sm font-medium">Ask at a different moment</h3>
              <span className="font-mono text-[11px] text-muted-foreground">
                {at === null ? "now" : `${at.replace("T", " ").slice(0, 19)}Z`}
              </span>
            </div>
            <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
              The bytes, the signature and the certificate do not change. Only the instant the verifier judges revocation
              and validity at does, and the answer is recomputed for real each time. Asking about another moment reads the
              revocation lists the CA had already published by then; it never issues one.
            </p>
            <ol className="mt-3 flex flex-wrap gap-2">
              {moments.map((moment) => {
                const selected = moment.id === "now" ? at === null : at === moment.at;
                const instant = moment.id === "now" ? null : moment.at;
                return (
                  <li key={moment.id}>
                    <button
                      type="button"
                      title={moment.detail}
                      aria-pressed={selected}
                      disabled={pending}
                      onClick={() => {
                        setAt(instant);
                        void run(instant);
                      }}
                      className={cn(
                        "rounded-lg border px-2.5 py-1.5 text-left transition-colors disabled:opacity-60",
                        selected ? "border-primary bg-primary/10" : "bg-card hover:bg-accent",
                      )}
                    >
                      <span className="block text-xs font-medium">{moment.label}</span>
                      <span className="block font-mono text-[10px] text-muted-foreground">{moment.at.replace("T", " ").slice(0, 19)}Z</span>
                    </button>
                  </li>
                );
              })}
            </ol>
            {at !== null && (
              <p className="mt-2 text-xs text-muted-foreground">
                Showing the answer as at the selected moment. Choose <span className="font-medium">Now</span> to return to the present.
              </p>
            )}
          </div>
        )}

        {notSigned && (
          <p className="rounded-lg border border-dashed px-4 py-6 text-center text-sm text-muted-foreground">
            This document has no signature yet, so there is nothing to verify.
          </p>
        )}

        {error && (
          <p role="alert" className="rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
            {error}
          </p>
        )}

        {!result && !pending && !notSigned && !error && (
          <p className="rounded-lg border border-dashed bg-muted/20 px-4 py-8 text-center text-sm text-muted-foreground">
            Nothing has been run yet. Verification reads the stored bytes, the certificate, the CRL and the time-stamp afresh each time.
          </p>
        )}

        {result && display && (
          <div className="animate-slide-up space-y-5">
            <div role="status" className={cn("flex flex-wrap items-start gap-4 rounded-xl border p-5", display.tone)}>
              <display.icon aria-hidden className="h-9 w-9 shrink-0" strokeWidth={1.75} />
              <div className="min-w-0 flex-1 space-y-1.5">
                <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                  <span className="text-xl font-semibold tracking-tight">{display.label}</span>
                  {result.reason && <span className="rounded-md border border-current/25 px-1.5 py-0.5 font-mono text-xs">{result.reason}</span>}
                </div>
                <p className="text-sm text-foreground/80">{display.summary}</p>
                <p className="text-sm text-foreground">{result.explanation}</p>
                <a
                  className="mt-2 inline-flex items-center gap-1.5 rounded-lg border border-current/30 px-2.5 py-1 text-xs font-medium hover:bg-current/10"
                  href={`/api/documents/${documentId}/evidence${version === undefined ? "" : `?version=${version}`}`}
                >
                  <Package aria-hidden className="h-3.5 w-3.5" /> Download the evidence
                </a>
              </div>
            </div>

            <EvidenceChain steps={result.steps.filter((step) => !step.id.includes(":"))} />

            <div className="grid items-start gap-5 3xl:grid-cols-[minmax(0,1fr)_20rem]">
            <ol aria-label="Verification steps" className="divide-y overflow-hidden rounded-xl border">
              {result.steps.map((step) => {
                const stepDisplay = STEP_DISPLAY[step.status];
                const sub = step.id.startsWith("certificate-validity:");
                return (
                  <li key={step.id} className={cn("flex gap-3 px-4 py-2.5 text-sm", sub && "bg-muted/25 pl-10")}>
                    <stepDisplay.icon aria-hidden className={cn("mt-0.5 h-4 w-4 shrink-0", stepDisplay.className)} />
                    <span className={cn("w-24 shrink-0 font-mono text-[11px] leading-5", stepDisplay.className)}>
                      {step.status}
                      {step.optional && step.status !== "PASS" ? " (optional)" : ""}
                    </span>
                    <span className="min-w-0">
                      <span className={cn(sub ? "text-muted-foreground" : "font-medium")}>{step.step}</span>
                      {step.detail && <span className="mt-0.5 block font-mono text-[11px] text-muted-foreground [overflow-wrap:anywhere]">{step.detail}</span>}
                    </span>
                  </li>
                );
              })}
            </ol>

            <div className="rounded-xl border p-4">
              <div className="mb-3 text-sm font-medium">Time and revocation</div>
              <dl className="grid gap-x-6 gap-y-3 sm:grid-cols-2 3xl:grid-cols-1">
                <TrustRow label="Trusted time-stamp" value={result.trust.trustedTime} />
                <TrustRow label="Time-Stamp Authority" value={result.trust.timestampAuthority} />
                <TrustRow label="Server clock at signing (not evidence)" value={result.trust.claimedSigningTime} />
                <TrustRow label="Certificate judged at" value={result.trust.certificateEvaluatedAt} />
                <TrustRow
                  label="Revocation"
                  value={
                    result.trust.revocation
                      ? `${result.trust.revocation.reason} at ${result.trust.revocation.revokedAt}${
                          result.trust.revocation.invalidityDate ? `, invalid from ${result.trust.revocation.invalidityDate}` : ""
                        }`
                      : "not revoked"
                  }
                />
                <TrustRow label="Policy decision" value={result.trust.revocationDecision} />
                <TrustRow label="Policy" value={result.trust.policy} />
              </dl>
            </div>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
