"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

type StepStatus = "PASS" | "FAIL" | "UNAVAILABLE" | "SKIPPED";

type VerificationStep = { step: string; status: StepStatus; passed: boolean; detail?: string };

type Outcome = "VALID" | "INVALID" | "UNVERIFIABLE" | "ERROR";

type VerificationResult = {
  outcome: Outcome;
  reason?: string;
  steps: VerificationStep[];
};

const OUTCOME_DISPLAY: Record<
  Outcome,
  { label: string; variant: "success" | "destructive" | "outline"; summary: string }
> = {
  VALID: {
    label: "AUTHENTIC",
    variant: "success",
    summary: "Every check passed.",
  },
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

const REASON_EXPLANATIONS: Record<string, string> = {
  HASH_MISMATCH:
    "The bytes stored for this document no longer hash to the value that was signed. The content changed after signing.",
  SIGNATURE_INVALID:
    "The signature does not verify under the public key in the certificate for this algorithm.",
  CERTIFICATE_EXPIRED: "The signing certificate is outside its validity period.",
  CERTIFICATE_REVOKED: "The signing certificate has been revoked.",
  CERTIFICATE_CHAIN_INVALID:
    "The certificate does not chain to this installation's CA, does not carry a document-signing profile, or its stored metadata disagrees with the certificate itself.",
  STORAGE_UNAVAILABLE:
    "The stored bytes could not be read, so the content could not be checked.",
  CERTIFICATE_NOT_FOUND:
    "The certificate this signature refers to cannot be found, so the signer cannot be established.",
  UNSUPPORTED_ALGORITHM:
    "This installation has no provider registered for the signature's algorithm.",
  INTERNAL_ERROR: "The verifier encountered an internal fault and could not finish.",
};

const STEP_STYLE: Record<StepStatus, string> = {
  PASS: "text-success",
  FAIL: "text-destructive",
  UNAVAILABLE: "text-amber-600",
  SKIPPED: "text-muted-foreground",
};

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
          Steps 1-8 of Figure 8, in order, each with its own result.
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

            {result.reason && (
              <p className="max-w-prose rounded-md border p-3 text-sm">
                {REASON_EXPLANATIONS[result.reason] ?? result.reason}
              </p>
            )}

            <ol className="space-y-2">
              {result.steps.map((step, index) => (
                <li
                  key={`${index}-${step.step}`}
                  className={`flex gap-3 rounded-md border px-3 py-2 text-sm ${
                    step.step.startsWith("4.") ? "ml-6 border-dashed" : ""
                  }`}
                >
                  <span className={`w-24 shrink-0 font-mono text-xs ${STEP_STYLE[step.status]}`}>
                    {step.status}
                  </span>
                  <span className="min-w-0">
                    <span className="font-medium">{step.step.replace(/^4\./, "")}</span>
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
