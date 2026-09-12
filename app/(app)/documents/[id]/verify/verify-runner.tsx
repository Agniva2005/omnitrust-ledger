"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

type VerificationStep = { step: string; passed: boolean; detail?: string };

type VerificationResult = {
  outcome: "AUTHENTIC" | "INVALID";
  reason?: string;
  steps: VerificationStep[];
};

const REASON_EXPLANATIONS: Record<string, string> = {
  HASH_MISMATCH:
    "The bytes stored for this document no longer hash to the value that was signed. The content changed after signing.",
  SIGNATURE_INVALID:
    "The signature does not verify under the public key in the certificate for this algorithm.",
  CERTIFICATE_EXPIRED: "The signing certificate is outside its validity period.",
  CERTIFICATE_REVOKED: "The signing certificate has been revoked.",
  CERTIFICATE_CHAIN_INVALID:
    "The certificate does not chain to this installation's root CA, or its stored metadata disagrees with the certificate itself.",
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

        {result && (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center gap-3">
              <Badge variant={result.outcome === "AUTHENTIC" ? "success" : "destructive"}>
                {result.outcome}
              </Badge>
              {result.reason && (
                <span className="font-mono text-sm text-destructive">{result.reason}</span>
              )}
            </div>

            {result.reason && (
              <p className="max-w-prose rounded-md border border-destructive/40 bg-destructive/5 p-3 text-sm">
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
                  <span
                    aria-hidden
                    className={step.passed ? "text-success" : "text-destructive"}
                  >
                    {step.passed ? "PASS" : "FAIL"}
                  </span>
                  <span className="sr-only">{step.passed ? "passed" : "failed"}</span>
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
