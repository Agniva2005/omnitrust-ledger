import Link from "next/link";
import { notFound, redirect } from "next/navigation";
import { VerifyRunner } from "@/app/(app)/documents/[id]/verify/verify-runner";
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
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Verify: {document.filename}</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Runs the eight-step verification workflow from report Figure 8. Every step is executed
          against the bytes on disk right now.
        </p>
      </div>

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
          <CardContent>
            <Button asChild variant="outline">
              <Link href={`/documents/${document.id}`}>Back to document</Link>
            </Button>
          </CardContent>
        </Card>
      ) : (
        <>
          <Card>
            <CardHeader>
              <CardTitle>What is being verified</CardTitle>
              <CardDescription>
                Signature on v{latest.documentVersion.versionNumber}, made with{" "}
                {orchestrator.describe(latest.algorithm as never).displayName} under certificate{" "}
                <span className="font-mono text-xs">{latest.certificate.serialNumber}</span>.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-1 break-all text-sm">
              <div>
                <span className="text-muted-foreground">Hash that was signed:</span>{" "}
                <span className="font-mono text-xs">{latest.documentVersion.hash}</span>
              </div>
              <div className="text-xs text-muted-foreground">
                The algorithm is resolved from the signature record, never hard-coded in the
                verification path.
              </div>
            </CardContent>
          </Card>

          <VerifyRunner documentId={document.id} />
        </>
      )}
    </div>
  );
}
