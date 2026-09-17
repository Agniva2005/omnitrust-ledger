import { ArrowLeft, CircleCheck, CircleHelp, CircleX, History, KeyRound, Link2, Package, ShieldCheck, ShieldX } from "lucide-react";
import Link from "next/link";
import { notFound, redirect } from "next/navigation";
import { CopyButton } from "@/components/copy-button";
import { PageHeader } from "@/components/page-header";
import { SecurityClassBadge } from "@/components/security-class-badge";
import { StatusBadge } from "@/components/status-badge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { buttonVariants } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { NotFoundError } from "@/lib/api";
import { getSession } from "@/lib/auth/session";
import { exploreCertificate } from "@/lib/pki/explorer";
import { cn } from "@/lib/utils";

export const dynamic = "force-dynamic";

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid gap-1 border-b py-2.5 last:border-b-0 sm:grid-cols-[10rem_1fr] sm:gap-4">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="min-w-0 [overflow-wrap:anywhere]">{children}</dd>
    </div>
  );
}

export default async function CertificateExplorerPage({ params }: { params: Promise<{ id: string }> }) {
  const actor = await getSession();
  if (!actor) redirect("/login");

  const { id } = await params;
  const certificate = await exploreCertificate(actor, id).catch((error) => {
    if (error instanceof NotFoundError) notFound();
    throw error;
  });

  const revocation = certificate.revocation;
  const revocationTone =
    revocation.status === "REVOKED"
      ? { variant: "destructive" as const, icon: ShieldX, className: "border-destructive/35 bg-destructive/[0.06] text-destructive" }
      : revocation.status === "UNAVAILABLE"
        ? { variant: "warning" as const, icon: CircleHelp, className: "border-warning/40 bg-warning/[0.07] text-warning" }
        : { variant: "success" as const, icon: ShieldCheck, className: "border-success/35 bg-success/[0.06] text-success" };
  const passed = certificate.validation.checks.filter((check) => check.passed).length;

  return (
    <div className="space-y-6">
      <PageHeader
        icon={ShieldCheck}
        eyebrow="Certificate explorer"
        title={certificate.subjectUser}
        description={<span className="font-mono text-xs [overflow-wrap:anywhere]">serial {certificate.serialNumber}</span>}
        actions={
          <div className="flex flex-wrap gap-2">
            <a className={cn(buttonVariants({ variant: "default", size: "sm" }))} href={`/api/certificates/${certificate.id}/evidence`}>
              <Package aria-hidden /> Evidence pack
            </a>
            <Button asChild variant="outline" size="sm">
              <Link href="/certificates">
                <ArrowLeft aria-hidden /> Certificates
              </Link>
            </Button>
          </div>
        }
      />

      <div className="flex flex-wrap items-center gap-2">
        <StatusBadge status={certificate.status} />
        <Badge variant="secondary">{certificate.algorithm}</Badge>
        {certificate.publicKey.securityClass && <SecurityClassBadge securityClass={certificate.publicKey.securityClass} />}
        <Badge variant={certificate.validation.valid ? "success" : "destructive"}>
          {certificate.validation.valid ? "validates now" : certificate.validation.reason}
        </Badge>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Link2 aria-hidden className="h-4 w-4 text-primary" /> Trust chain
          </CardTitle>
          <CardDescription>
            Each link is checked against the certificate bytes: the issuer name, the CA&apos;s signature over the certificate, and each certificate&apos;s profile and
            validity.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-5">
          <ol className="space-y-0">
            {certificate.chain.map((link, index) => (
              <li key={link.role}>
                {index > 0 && <div aria-hidden className="ml-6 h-5 border-l-2 border-dashed border-primary/30" />}
                <div className="rounded-xl border bg-muted/20 p-4">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge variant={index === 0 ? "default" : "secondary"}>{link.role}</Badge>
                    <span className="text-xs text-muted-foreground">{link.algorithm}</span>
                    {link.selfSigned && <Badge variant="outline">self-signed</Badge>}
                  </div>
                  <div className="mt-2 text-sm font-medium [overflow-wrap:anywhere]">{link.subject}</div>
                  <div className="mt-0.5 text-xs text-muted-foreground [overflow-wrap:anywhere]">
                    issued by {link.issuer} · valid {link.notBefore.slice(0, 10)} to {link.notAfter.slice(0, 10)}
                  </div>
                  <div className="mt-1.5 font-mono text-[11px] text-muted-foreground [overflow-wrap:anywhere]">SHA-256 {link.fingerprintSha256}</div>
                </div>
              </li>
            ))}
          </ol>
          <div>
            <div className="mb-2 text-xs font-medium text-muted-foreground">
              {passed} of {certificate.validation.checks.length} checks passed
            </div>
            <ul className="grid gap-x-6 gap-y-1.5 text-sm sm:grid-cols-2">
              {certificate.validation.checks.map((check) => (
                <li key={check.step} className="flex items-start gap-2">
                  {check.passed ? (
                    <CircleCheck aria-hidden className="mt-0.5 h-4 w-4 shrink-0 text-success" />
                  ) : (
                    <CircleX aria-hidden className="mt-0.5 h-4 w-4 shrink-0 text-destructive" />
                  )}
                  <span>
                    {check.step}
                    <span className="sr-only">{check.passed ? " passed" : " failed"}</span>
                  </span>
                </li>
              ))}
            </ul>
          </div>
        </CardContent>
      </Card>

      <div className="grid gap-6 lg:grid-cols-[minmax(0,1.15fr)_minmax(0,1fr)]">
        <Card>
          <CardHeader>
            <CardTitle>Certificate fields</CardTitle>
            <CardDescription>Parsed from the X.509 structure.</CardDescription>
          </CardHeader>
          <CardContent>
            <dl className="text-sm">
              <Field label="Subject">{certificate.subject}</Field>
              <Field label="Issuer">{certificate.issuer}</Field>
              <Field label="Validity">
                {certificate.notBefore} to {certificate.notAfter}
              </Field>
              <Field label="Signed by CA with">{certificate.signedBy}</Field>
              <Field label="Public key">
                {certificate.publicKey.algorithm}
                {certificate.publicKey.bytes !== null && `, ${certificate.publicKey.bytes}-byte key`}
                {certificate.publicKey.oid && <span className="font-mono text-xs text-muted-foreground"> ({certificate.publicKey.oid})</span>}
                {!certificate.publicKey.matchesRecord && <span className="text-destructive"> — does not match the stored algorithm</span>}
              </Field>
              <Field label="Basic constraints">
                {certificate.extensions.basicConstraints
                  ? `cA=${certificate.extensions.basicConstraints.ca ? "TRUE" : "FALSE"}${certificate.extensions.basicConstraints.critical ? " (critical)" : ""}`
                  : "absent"}
              </Field>
              <Field label="Key usage">
                {certificate.extensions.keyUsage
                  ? `${certificate.extensions.keyUsage.names.join(", ")}${certificate.extensions.keyUsage.critical ? " (critical)" : ""}`
                  : "absent"}
              </Field>
              <Field label="Extended key usage">{certificate.extensions.extendedKeyUsage.join(", ") || "none"}</Field>
              <Field label="SHA-256 fingerprint">
                <span className="font-mono text-xs">{certificate.fingerprintSha256}</span>
              </Field>
            </dl>
            <details className="mt-4 text-sm">
              <summary className="w-fit cursor-pointer text-muted-foreground hover:text-foreground">PEM</summary>
              <div className="mt-2 space-y-2">
                <CopyButton value={certificate.pem} label="Copy PEM" />
                <pre className="overflow-x-auto rounded-lg border bg-muted/50 p-3 font-mono text-[11px]">{certificate.pem}</pre>
              </div>
            </details>
          </CardContent>
        </Card>

        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Revocation</CardTitle>
              <CardDescription>{revocation.detail}</CardDescription>
            </CardHeader>
            <CardContent>
              <div className={cn("flex items-start gap-3 rounded-lg border p-3", revocationTone.className)}>
                <revocationTone.icon aria-hidden className="h-6 w-6 shrink-0" strokeWidth={1.75} />
                <div className="min-w-0 space-y-1">
                  <div className="font-semibold tracking-tight">{revocation.status.replace("_", " ")}</div>
                  {revocation.reason && (
                    <div className="text-sm text-foreground">
                      {revocation.reason} at <span className="font-mono text-xs">{revocation.revokedAt}</span>
                      {revocation.invalidityDate && (
                        <>
                          , invalid from <span className="font-mono text-xs">{revocation.invalidityDate}</span>
                        </>
                      )}
                    </div>
                  )}
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <KeyRound aria-hidden className="h-4 w-4 text-primary" /> Key lifecycle
              </CardTitle>
              <CardDescription>NIST SP 800-57 aligned states (report Figure 7); history from the audit log.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-5 text-sm">
              <ol aria-label="Key states" className="grid grid-cols-5 gap-1">
                {certificate.key.states.map((state) => {
                  const current = state === certificate.key.state;
                  const next = certificate.key.nextStates.includes(state);
                  return (
                    <li key={state} aria-current={current ? "step" : undefined} className="min-w-0">
                      <div className={cn("h-1.5 rounded-full", current ? "bg-primary" : next ? "bg-primary/30" : "bg-muted")} />
                      <div className={cn("mt-1.5 truncate text-[10px] font-medium uppercase tracking-wide", current ? "text-primary" : "text-muted-foreground")} title={state}>
                        {state}
                      </div>
                    </li>
                  );
                })}
              </ol>
              <p className="text-xs text-muted-foreground">
                Current: {certificate.key.state}. Legal next: {certificate.key.nextStates.join(", ") || "none (terminal)"}.
              </p>
              <ol className="relative space-y-3 border-l pl-5">
                {certificate.lifecycle.map((entry) => (
                  <li key={entry.seq} className="relative">
                    <span aria-hidden className="absolute -left-[1.53rem] top-1.5 h-2.5 w-2.5 rounded-full bg-primary ring-4 ring-card" />
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge variant={entry.action === "CERTIFICATE_REVOKED" ? "destructive" : "secondary"}>{entry.action}</Badge>
                      {typeof entry.metadata.from === "string" && (
                        <span className="font-mono text-xs">
                          {String(entry.metadata.from)} → {String(entry.metadata.to)}
                        </span>
                      )}
                      {typeof entry.metadata.reason === "string" && <span className="text-xs">{entry.metadata.reason}</span>}
                    </div>
                    <div className="mt-0.5 text-xs text-muted-foreground">
                      #{entry.seq} · {entry.at.replace("T", " ").slice(0, 19)} UTC · {entry.by ?? "system"}
                    </div>
                  </li>
                ))}
              </ol>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <History aria-hidden className="h-4 w-4 text-primary" /> Signatures made with this key
              </CardTitle>
              <CardDescription>{certificate.signatures.count} in total.</CardDescription>
            </CardHeader>
            <CardContent>
              {certificate.signatures.recent.length === 0 ? (
                <p className="text-sm text-muted-foreground">None yet.</p>
              ) : (
                <ul className="divide-y text-sm">
                  {certificate.signatures.recent.map((signature) => (
                    <li key={signature.id} className="flex flex-wrap items-center gap-2 py-2.5">
                      <Link href={`/documents/${signature.documentId}`} className="min-w-0 truncate font-medium hover:underline">
                        {signature.filename}
                      </Link>
                      <span className="font-mono text-xs text-muted-foreground">v{signature.versionNumber}</span>
                      {signature.timestamped && <Badge variant="outline">time-stamped</Badge>}
                      <span className="ml-auto font-mono text-xs text-muted-foreground">{signature.signedAt.slice(0, 19).replace("T", " ")}</span>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
