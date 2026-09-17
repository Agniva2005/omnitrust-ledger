// The one page in this application a visitor without an account can reach.
//
// It shows a single shared version of a single document, and it verifies it there and then
// rather than reporting a verdict somebody else recorded earlier. The recipient is told what
// that proves and, just as plainly, what it does not.
import { CircleAlert, CircleCheck, CircleHelp, CircleX, Clock, FileText, Package, ShieldCheck } from "lucide-react";
import type { Metadata } from "next";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { orchestrator } from "@/lib/crypto/orchestrator";
import { ShareUnavailableError, openShare } from "@/lib/documents/sharing";
import { signaturesForDocument } from "@/lib/documents/signing";
import { verifyDocument } from "@/lib/documents/verification";
import { cn } from "@/lib/utils";

export const dynamic = "force-dynamic";

// A shared link should not turn up in a search engine.
export const metadata: Metadata = { robots: { index: false, follow: false } };

const OUTCOME = {
  VALID: {
    label: "AUTHENTIC",
    lead: "This document is unchanged since it was signed, and the signature checks out.",
    tone: "border-success/40 bg-success/[0.07] text-success",
    icon: CircleCheck,
  },
  INVALID: {
    label: "INVALID",
    lead: "There is positive evidence that this document cannot be trusted.",
    tone: "border-destructive/40 bg-destructive/[0.07] text-destructive",
    icon: CircleX,
  },
  UNVERIFIABLE: {
    label: "UNVERIFIABLE",
    lead: "Something needed to decide could not be obtained. This is not a finding either way.",
    tone: "border-warning/45 bg-warning/[0.08] text-warning",
    icon: CircleHelp,
  },
  ERROR: {
    label: "VERIFICATION ERROR",
    lead: "The checker itself failed, so this result supports no conclusion.",
    tone: "border-destructive/40 bg-destructive/[0.07] text-destructive",
    icon: CircleAlert,
  },
} as const;

function Shell({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-background">
      <header className="border-b">
        <div className="mx-auto flex h-16 w-full max-w-4xl items-center gap-2.5 px-4 sm:px-6">
          <span aria-hidden className="grid h-8 w-8 place-items-center rounded-lg bg-gradient-to-br from-primary to-hybrid text-[11px] font-bold text-primary-foreground shadow-sm">
            OT
          </span>
          <div className="leading-tight">
            <div className="text-sm font-semibold tracking-tight">OmniTrust Ledger</div>
            <div className="text-[11px] text-muted-foreground">Shared document</div>
          </div>
        </div>
      </header>
      <main className="mx-auto w-full max-w-4xl space-y-6 px-4 py-10 sm:px-6">{children}</main>
    </div>
  );
}

function Field({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="rounded-lg border bg-muted/30 p-3">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className={cn("mt-1 text-sm [overflow-wrap:anywhere]", mono && "font-mono text-xs")}>{value}</dd>
    </div>
  );
}

export default async function SharePage({ params }: { params: Promise<{ token: string }> }) {
  const { token } = await params;

  let share: Awaited<ReturnType<typeof openShare>>;
  try {
    share = await openShare(token);
  } catch (error) {
    const reason = error instanceof ShareUnavailableError ? error.message : "This link could not be opened.";
    return (
      <Shell>
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <CircleAlert aria-hidden className="h-5 w-5 text-warning" /> This link is not available
            </CardTitle>
            <CardDescription>{reason}</CardDescription>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground">
              Links are time-limited and can be withdrawn at any moment by the person who shared them. Ask them for a new
              one if you still need access.
            </p>
          </CardContent>
        </Card>
      </Shell>
    );
  }

  // Verified now, for this visitor, rather than replaying a verdict recorded earlier.
  const result = await verifyDocument({ userId: "", email: "", role: "VERIFIER" }, share.documentId, {
    versionNumber: share.versionNumber,
    viaShareToken: true,
  });
  const display = OUTCOME[result.outcome];
  const signatures = await signaturesForDocument(share.documentId);
  const signature = signatures.find((candidate) => candidate.documentVersion.versionNumber === share.versionNumber);

  return (
    <Shell>
      <div>
        <p className="text-xs uppercase tracking-wide text-muted-foreground">Shared with you</p>
        <h1 className="mt-1 flex items-center gap-2 text-2xl font-semibold tracking-tight [overflow-wrap:anywhere]">
          <FileText aria-hidden className="h-6 w-6 shrink-0 text-primary" />
          {share.filename}
        </h1>
        <p className="mt-2 text-sm text-muted-foreground">
          Shared by <span className="font-medium text-foreground">{share.sharedBy}</span> with{" "}
          <span className="font-medium text-foreground">{share.audience}</span> on {share.sharedAt.slice(0, 10)}.
        </p>
        {share.note && <p className="mt-2 max-w-2xl rounded-lg border bg-muted/30 p-3 text-sm">{share.note}</p>}
      </div>

      <div role="status" className={cn("flex flex-wrap items-start gap-4 rounded-xl border p-5", display.tone)}>
        <display.icon aria-hidden className="h-9 w-9 shrink-0" strokeWidth={1.75} />
        <div className="min-w-0 flex-1 space-y-1.5">
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
            <span className="text-xl font-semibold tracking-tight">{display.label}</span>
            {result.reason && <span className="rounded-md border border-current/25 px-1.5 py-0.5 font-mono text-xs">{result.reason}</span>}
          </div>
          <p className="text-sm text-foreground/80">{display.lead}</p>
          <p className="text-sm text-foreground">{result.explanation}</p>
          <a
            className="mt-2 inline-flex items-center gap-1.5 rounded-lg border border-current/30 px-2.5 py-1 text-xs font-medium hover:bg-current/10"
            href={`/api/share/${token}/evidence`}
          >
            <Package aria-hidden className="h-3.5 w-3.5" /> Download the evidence
          </a>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>What was checked</CardTitle>
          <CardDescription>
            Ten ordered checks, run against the stored bytes just now. The hash is recomputed from what is on disk every
            time, so a document altered after signing fails here rather than passing quietly.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ol className="divide-y overflow-hidden rounded-xl border">
            {result.steps
              .filter((step) => !step.id.includes(":"))
              .map((step) => (
                <li key={step.id} className="flex gap-3 px-4 py-2.5 text-sm">
                  <span
                    className={cn(
                      "w-24 shrink-0 font-mono text-[11px] leading-5",
                      step.status === "PASS" && "text-success",
                      step.status === "FAIL" && "text-destructive",
                      step.status === "UNAVAILABLE" && "text-warning",
                      step.status === "SKIPPED" && "text-muted-foreground",
                    )}
                  >
                    {step.status}
                  </span>
                  <span className="min-w-0">
                    <span className="block">{step.step}</span>
                    {step.detail && <span className="mt-0.5 block font-mono text-[11px] leading-relaxed text-muted-foreground [overflow-wrap:anywhere]">{step.detail}</span>}
                  </span>
                </li>
              ))}
          </ol>
        </CardContent>
      </Card>

      <div className="grid gap-6 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ShieldCheck aria-hidden className="h-4 w-4 text-primary" /> The signature
            </CardTitle>
          </CardHeader>
          <CardContent>
            <dl className="grid gap-2">
              <Field label="Version" value={`v${share.versionNumber}`} />
              {signature && <Field label="Algorithm" value={orchestrator.displayName(signature.algorithm)} />}
              {signature && <Field label="Signed by" value={signature.signedBy.email} />}
              {signature && <Field label="Certificate serial" value={signature.certificate.serialNumber} mono />}
              {result.trust.trustedTime && <Field label="Trusted time-stamp" value={result.trust.trustedTime.replace("T", " ").slice(0, 19)} mono />}
            </dl>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Clock aria-hidden className="h-4 w-4 text-primary" /> This link
            </CardTitle>
          </CardHeader>
          <CardContent>
            <dl className="grid gap-2">
              <Field label="Expires" value={share.expiresAt.replace("T", " ").slice(0, 19)} mono />
              <Field label="Opened" value={`${share.accessCount} time${share.accessCount === 1 ? "" : "s"}`} />
            </dl>
            <p className="mt-3 text-xs leading-relaxed text-muted-foreground">
              Every opening of this link is written to a hash-chained audit log, so the person who shared it keeps a record
              of when it was used that cannot be quietly altered. They can withdraw it at any time.
            </p>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>What this does and does not prove</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm leading-relaxed text-muted-foreground">
          <p>
            <span className="font-medium text-foreground">It shows</span> that these exact bytes carry a signature made
            with the named certificate, that the certificate was issued by this installation&apos;s authority and was
            valid and unrevoked at the time the signature is proven to have existed, and that nothing has changed since.
          </p>
          <p>
            <span className="font-medium text-foreground">It does not show</span> that anyone outside this installation
            trusts the issuing authority: it is a local, self-signed certificate authority. Take the evidence pack and
            check it with your own tools rather than relying on this page — it contains the document, the signature, the
            certificates and the revocation list, with the commands to verify them.
          </p>
        </CardContent>
      </Card>
    </Shell>
  );
}
