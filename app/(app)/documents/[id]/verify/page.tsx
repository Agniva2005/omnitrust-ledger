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

export const dynamic = "force-dynamic";

export default async function VerifyPage({ params }: { params: Promise<{ id: string }> }) {
  const actor = await getSession();
  if (!actor) redirect("/login");

  const { id } = await params;
  const document = await getDocument(actor, id).catch((error) => {
    if (error instanceof NotFoundError) notFound();
    throw error;
  });

  const signatures = await signaturesForDocument(document.id);
  const latest = signatures.find(
    (signature) => signature.documentVersion.versionNumber === document.versions[0]?.versionNumber,
  );

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
        <Card>
          <CardHeader>
            <CardTitle>Not yet signed</CardTitle>
            <CardDescription>
              Version {document.versions[0]?.versionNumber} of this document has no signature, so
              there is nothing to verify. This is neither authentic nor invalid.
            </CardDescription>
          </CardHeader>
        </Card>
      ) : (
        <>
          <Card>
            <CardHeader>
              <CardTitle>What is being verified</CardTitle>
              <CardDescription>
                Signature on v{latest.documentVersion.versionNumber}, made with{" "}
                {orchestrator.displayName(latest.algorithm)} under certificate{" "}
                <span className="font-mono text-xs">{latest.certificate.serialNumber}</span>.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <dl className="grid gap-3 text-sm sm:grid-cols-3">
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

          <VerifyRunner documentId={document.id} />
        </>
      )}
    </div>
  );
}
