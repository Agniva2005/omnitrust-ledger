import { ArrowLeft, Fingerprint, KeyRound, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { notFound, redirect } from "next/navigation";
import { VerifyRunner } from "@/app/(app)/documents/[id]/verify/verify-runner";
import { PageHeader } from "@/components/page-header";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { NotFoundError } from "@/lib/api";
import { can } from "@/lib/auth/rbac";
import { getSession } from "@/lib/auth/session";
import { orchestrator } from "@/lib/crypto/orchestrator";
import { getDocument } from "@/lib/documents/service";
import { signaturesForDocument } from "@/lib/documents/signing";
import { verificationMoments } from "@/lib/documents/timeline";
import { cn } from "@/lib/utils";

export const dynamic = "force-dynamic";

export default async function VerifyPage({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ version?: string }>;
}) {
  const actor = await getSession();
  if (!actor) redirect("/login");

  const { id } = await params;
  const document = await getDocument(actor, id).catch((error) => {
    if (error instanceof NotFoundError) notFound();
    throw error;
  });

  const signatures = await signaturesForDocument(document.id);

  // ?version=N verifies that version instead of the latest, so an earlier signed version can
  // be checked after a new one has been uploaded. An absent or unknown value falls back.
  const requested = Number.parseInt((await searchParams).version ?? "", 10);
  const targetVersion = document.versions.some((version) => version.versionNumber === requested)
    ? requested
    : document.versions[0]?.versionNumber;
  const latest = signatures.find(
    (signature) => signature.documentVersion.versionNumber === targetVersion,
  );

  // The instants at which this signature's verdict could differ, taken from its own record.
  const moments = latest ? await verificationMoments(document.id, targetVersion) : [];

  const versionSwitcher =
    document.versions.length > 1 ? (
      <div className="flex flex-wrap items-center gap-2 rounded-xl border bg-card p-3 shadow-card">
        <span className="text-xs text-muted-foreground">Verify version:</span>
        {[...document.versions]
          .sort((a, b) => a.versionNumber - b.versionNumber)
          .map((version) => {
            const signed = signatures.some(
              (signature) => signature.documentVersion.versionNumber === version.versionNumber,
            );
            const active = version.versionNumber === targetVersion;
            return (
              <Link
                key={version.id}
                href={`/documents/${document.id}/verify?version=${version.versionNumber}`}
                aria-current={active ? "page" : undefined}
                className={cn(
                  "rounded-lg border px-2.5 py-1 font-mono text-xs transition-colors",
                  active ? "border-primary bg-primary/10 text-foreground" : "text-muted-foreground hover:bg-accent",
                )}
              >
                v{version.versionNumber}
                {!signed && <span className="ml-1.5 font-sans text-[10px]">unsigned</span>}
              </Link>
            );
          })}
      </div>
    ) : null;

  return (
    <div className="space-y-6">
      <PageHeader
        icon={Fingerprint}
        eyebrow="Verification"
        title={`Verify: ${document.filename}`}
        description="Runs the verification workflow from report Figure 8, extended with a trusted time-stamp and CRL-based revocation (ten steps). Every step is executed against the bytes on disk right now."
        actions={
          <Button asChild variant="outline">
            <Link href={`/documents/${document.id}`}>
              <ArrowLeft aria-hidden /> Back to document
            </Link>
          </Button>
        }
      />

      {!can(actor.role, "document:verify") ? (
        <Card>
          <CardHeader>
            <CardTitle>Not permitted</CardTitle>
            <CardDescription>Role {actor.role} cannot verify documents.</CardDescription>
          </CardHeader>
        </Card>
      ) : !latest ? (
        <div className="space-y-4">
          {versionSwitcher}
          <Card>
            <CardHeader>
              <CardTitle>Not yet signed</CardTitle>
              <CardDescription>
                Version {targetVersion} of this document has no signature, so there is nothing to
                verify. This is neither authentic nor invalid.
                {document.versions.length > 1 && " An earlier version can be verified above."}
              </CardDescription>
            </CardHeader>
          </Card>
        </div>
      ) : (
        <div className="grid items-start gap-6 2xl:grid-cols-[minmax(0,1fr)_22rem] 3xl:grid-cols-[minmax(0,1fr)_26rem]">
          <Card className="2xl:sticky 2xl:top-20 2xl:col-start-2 2xl:row-start-1">
            <CardHeader>
              <CardTitle>What is being verified</CardTitle>
              <CardDescription>
                Signature on v{latest.documentVersion.versionNumber}, made with{" "}
                {orchestrator.displayName(latest.algorithm)} under certificate{" "}
                <span className="font-mono text-xs">{latest.certificate.serialNumber}</span>.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <dl className="grid gap-3 text-sm sm:grid-cols-3 2xl:grid-cols-1">
                <div className="rounded-lg border bg-muted/30 p-3">
                  <dt className="flex items-center gap-1.5 text-xs text-muted-foreground">
                    <KeyRound aria-hidden className="h-3.5 w-3.5" /> Algorithm (from the signature record)
                  </dt>
                  <dd className="mt-1 font-medium">{orchestrator.displayName(latest.algorithm)}</dd>
                </div>
                <div className="rounded-lg border bg-muted/30 p-3">
                  <dt className="flex items-center gap-1.5 text-xs text-muted-foreground">
                    <ShieldCheck aria-hidden className="h-3.5 w-3.5" /> Certificate serial
                  </dt>
                  <dd className="mt-1 break-all font-mono text-xs">
                    <Link href={`/certificates/${latest.certificate.id}`} className="hover:underline">
                      {latest.certificate.serialNumber}
                    </Link>
                  </dd>
                </div>
                <div className="rounded-lg border bg-muted/30 p-3">
                  <dt className="text-xs text-muted-foreground">Hash that was signed:</dt>
                  <dd className="mt-1 break-all font-mono text-xs">{latest.documentVersion.hash}</dd>
                </div>
              </dl>
              <p className="mt-3 text-xs text-muted-foreground">
                The algorithm is resolved from the signature record, never hard-coded in the verification path.
              </p>
            </CardContent>
          </Card>

          <div className="min-w-0 space-y-4 2xl:col-start-1 2xl:row-start-1">
            {versionSwitcher}
            <VerifyRunner documentId={document.id} version={targetVersion} moments={moments} />
          </div>
        </div>
      )}
    </div>
  );
}
