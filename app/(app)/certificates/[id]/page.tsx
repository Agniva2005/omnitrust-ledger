import Link from "next/link";
import { notFound, redirect } from "next/navigation";
import { StatusBadge } from "@/components/status-badge";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { NotFoundError } from "@/lib/api";
import { getSession } from "@/lib/auth/session";
import { exploreCertificate } from "@/lib/pki/explorer";

export const dynamic = "force-dynamic";

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid gap-1 sm:grid-cols-[11rem_1fr]">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="min-w-0 break-all">{children}</dd>
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

  const revocationVariant =
    certificate.revocation.status === "REVOKED" ? "destructive" : certificate.revocation.status === "UNAVAILABLE" ? "outline" : "success";

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-sm text-muted-foreground">
            <Link href="/certificates" className="hover:underline">
              Certificates
            </Link>{" "}
            / explorer
          </p>
          <h1 className="mt-1 text-2xl font-semibold tracking-tight">{certificate.subjectUser}</h1>
          <p className="mt-1 font-mono text-xs text-muted-foreground">serial {certificate.serialNumber}</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <StatusBadge status={certificate.status} />
          <Badge variant="secondary">{certificate.algorithm}</Badge>
          <Badge variant={certificate.validation.valid ? "success" : "destructive"}>
            {certificate.validation.valid ? "validates now" : certificate.validation.reason}
          </Badge>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Trust chain</CardTitle>
          <CardDescription>
            Each link is checked against the certificate bytes: the issuer name, the CA&apos;s signature over the
            certificate, and each certificate&apos;s profile and validity.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ol className="space-y-3">
            {certificate.chain.map((link, index) => (
              <li key={link.role}>
                {index > 0 && (
                  <div aria-hidden className="ml-6 h-4 border-l-2 border-dashed border-muted-foreground/40" />
                )}
                <div className="rounded-lg border p-4">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge variant={index === 0 ? "default" : "secondary"}>{link.role}</Badge>
                    <span className="text-xs text-muted-foreground">{link.algorithm}</span>
                    {link.selfSigned && <span className="text-xs text-muted-foreground">self-signed</span>}
                  </div>
                  <div className="mt-2 text-sm font-medium">{link.subject}</div>
                  <div className="text-xs text-muted-foreground">
                    issued by {link.issuer} · valid {link.notBefore.slice(0, 10)} to {link.notAfter.slice(0, 10)}
                  </div>
                  <div className="mt-1 break-all font-mono text-[11px] text-muted-foreground">SHA-256 {link.fingerprintSha256}</div>
                </div>
              </li>
            ))}
          </ol>
          <ul className="mt-4 grid gap-1 text-sm sm:grid-cols-2">
            {certificate.validation.checks.map((check) => (
              <li key={check.step} className="flex gap-2">
                <span className={check.passed ? "text-success" : "text-destructive"} aria-hidden>
                  {check.passed ? "✓" : "✕"}
                </span>
                <span>
                  {check.step}
                  <span className="sr-only">{check.passed ? " passed" : " failed"}</span>
                </span>
              </li>
            ))}
          </ul>
        </CardContent>
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Certificate fields</CardTitle>
            <CardDescription>Parsed from the X.509 structure.</CardDescription>
          </CardHeader>
          <CardContent>
            <dl className="space-y-2 text-sm">
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
              <summary className="cursor-pointer text-muted-foreground">PEM</summary>
              <pre className="mt-2 overflow-x-auto rounded-md border bg-muted p-3 text-[11px]">{certificate.pem}</pre>
            </details>
          </CardContent>
        </Card>

        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Revocation</CardTitle>
              <CardDescription>{certificate.revocation.detail}</CardDescription>
            </CardHeader>
            <CardContent className="space-y-1 text-sm">
              <Badge variant={revocationVariant}>{certificate.revocation.status.replace("_", " ")}</Badge>
              {certificate.revocation.reason && (
                <div>
                  {certificate.revocation.reason} at <span className="font-mono text-xs">{certificate.revocation.revokedAt}</span>
                  {certificate.revocation.invalidityDate && (
                    <>
                      , invalid from <span className="font-mono text-xs">{certificate.revocation.invalidityDate}</span>
                    </>
                  )}
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">Key lifecycle</CardTitle>
              <CardDescription>NIST SP 800-57 aligned states (report Figure 7); history from the audit log.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4 text-sm">
              <ol className="flex flex-wrap items-center gap-2" aria-label="Key states">
                {certificate.key.states.map((state, index) => (
                  <li key={state} className="flex items-center gap-2">
                    {index > 0 && <span aria-hidden className="text-muted-foreground">→</span>}
                    <Badge
                      variant={state === certificate.key.state ? "default" : certificate.key.nextStates.includes(state) ? "outline" : "secondary"}
                      aria-current={state === certificate.key.state ? "step" : undefined}
                    >
                      {state}
                    </Badge>
                  </li>
                ))}
              </ol>
              <p className="text-xs text-muted-foreground">
                Current: {certificate.key.state}. Legal next: {certificate.key.nextStates.join(", ") || "none (terminal)"}.
              </p>
              <ol className="relative space-y-2 border-l pl-5">
                {certificate.lifecycle.map((entry) => (
                  <li key={entry.seq}>
                    <span aria-hidden className="absolute -left-[5px] mt-1.5 h-2.5 w-2.5 rounded-full bg-primary" />
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge variant={entry.action === "CERTIFICATE_REVOKED" ? "destructive" : "secondary"}>{entry.action}</Badge>
                      {typeof entry.metadata.from === "string" && (
                        <span className="font-mono text-xs">
                          {String(entry.metadata.from)} → {String(entry.metadata.to)}
                        </span>
                      )}
                      {typeof entry.metadata.reason === "string" && <span className="text-xs">{entry.metadata.reason}</span>}
                    </div>
                    <div className="text-xs text-muted-foreground">
                      #{entry.seq} · {entry.at.replace("T", " ").slice(0, 19)} · {entry.by ?? "system"}
                    </div>
                  </li>
                ))}
              </ol>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">Signatures made with this key</CardTitle>
              <CardDescription>{certificate.signatures.count} in total.</CardDescription>
            </CardHeader>
            <CardContent>
              {certificate.signatures.recent.length === 0 ? (
                <p className="text-sm text-muted-foreground">None yet.</p>
              ) : (
                <ul className="divide-y text-sm">
                  {certificate.signatures.recent.map((signature) => (
                    <li key={signature.id} className="flex flex-wrap items-center gap-2 py-2">
                      <Link href={`/documents/${signature.documentId}`} className="font-medium hover:underline">
                        {signature.filename}
                      </Link>
                      <span className="text-xs text-muted-foreground">v{signature.versionNumber}</span>
                      {signature.timestamped && <Badge variant="outline">time-stamped</Badge>}
                      <span className="ml-auto text-xs text-muted-foreground">{signature.signedAt.slice(0, 19).replace("T", " ")}</span>
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
