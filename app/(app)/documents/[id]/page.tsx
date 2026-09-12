import Link from "next/link";
import { notFound, redirect } from "next/navigation";
import { SignPanel, type CertificateOption } from "@/app/(app)/documents/[id]/sign-panel";
import { StatusBadge } from "@/components/status-badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { NotFoundError } from "@/lib/api";
import { can } from "@/lib/auth/rbac";
import { getSession } from "@/lib/auth/session";
import { orchestrator } from "@/lib/crypto/orchestrator";
import { assertDocumentState, nextStates } from "@/lib/documents/lifecycle";
import { getDocument } from "@/lib/documents/service";
import { signaturesForDocument } from "@/lib/documents/signing";
import { signableCertificates } from "@/lib/pki/certificates";

export const dynamic = "force-dynamic";

export default async function DocumentDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const actor = await getSession();
  if (!actor) redirect("/login");

  const { id } = await params;
  const document = await getDocument(actor, id).catch((error) => {
    if (error instanceof NotFoundError) notFound();
    throw error;
  });

  const signatures = await signaturesForDocument(document.id);
  const latestVersion = document.versions[0];
  const latestSigned = signatures.some(
    (signature) => signature.documentVersion.versionNumber === latestVersion?.versionNumber,
  );

  const certificates: CertificateOption[] = can(actor.role, "document:sign")
    ? (await signableCertificates(actor)).map((certificate) => ({
        id: certificate.id,
        algorithm: certificate.algorithm,
        displayName: orchestrator.describe(certificate.algorithm as never).displayName,
        serialNumber: certificate.serialNumber,
        expiresAt: certificate.expiresAt.toISOString(),
      }))
    : [];

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">{document.filename}</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Owned by {document.owner.email} &middot; {document.mimeType}
          </p>
        </div>
        {can(actor.role, "document:verify") && (
          <Button asChild variant={signatures.length > 0 ? "default" : "outline"}>
            <Link href={`/documents/${document.id}/verify`}>Verify</Link>
          </Button>
        )}
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Lifecycle</CardTitle>
          <CardDescription>
            State machine from report Figure 4, enforced in lib/documents/lifecycle.ts.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3 text-sm">
          <div className="flex items-center gap-2">
            <span className="text-muted-foreground">Current state:</span>
            <StatusBadge status={document.status} />
          </div>
          <div className="text-muted-foreground">
            Legal next states:{" "}
            <span className="font-mono text-xs">
              {nextStates(assertDocumentState(document.status)).join(", ") || "none (terminal)"}
            </span>
          </div>
          <div className="break-all">
            <span className="text-muted-foreground">Current SHA-256:</span>{" "}
            <span className="font-mono text-xs">{document.currentHash}</span>
          </div>
        </CardContent>
      </Card>

      {can(actor.role, "document:sign") && (
        <Card>
          <CardHeader>
            <CardTitle>Sign</CardTitle>
            <CardDescription>
              {latestSigned
                ? `Version ${latestVersion?.versionNumber} is already signed. Upload a new version to sign again.`
                : "The orchestrator signs the 32 raw bytes of the current version's SHA-256."}
            </CardDescription>
          </CardHeader>
          <CardContent>
            {latestSigned ? (
              <p className="text-sm text-muted-foreground">
                One signature per version keeps verification unambiguous about which hash was
                signed.
              </p>
            ) : (
              <SignPanel documentId={document.id} certificates={certificates} />
            )}
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Signatures</CardTitle>
          <CardDescription>
            Each signature is bound to one document version and one certificate.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {signatures.length === 0 ? (
            <p className="text-sm text-muted-foreground">Not yet signed.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Version</TableHead>
                  <TableHead>Algorithm</TableHead>
                  <TableHead>Size</TableHead>
                  <TableHead>Certificate</TableHead>
                  <TableHead>Signer</TableHead>
                  <TableHead>Signed at</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {signatures.map((signature) => (
                  <TableRow key={signature.id}>
                    <TableCell>v{signature.documentVersion.versionNumber}</TableCell>
                    <TableCell>
                      {orchestrator.describe(signature.algorithm as never).displayName}
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {signature.signatureBytes.length} bytes
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {signature.certificate.serialNumber.slice(0, 12)}...{" "}
                      {signature.certificate.status !== "ACTIVE" && (
                        <StatusBadge status={signature.certificate.status} />
                      )}
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {signature.signedBy.email}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {signature.signedAt.toISOString()}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Versions</CardTitle>
          <CardDescription>
            Each version records the hash of the bytes stored for it. Blobs are encrypted at rest
            with AES-256-GCM.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Version</TableHead>
                <TableHead>SHA-256</TableHead>
                <TableHead>Stored at</TableHead>
                <TableHead>Created</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {document.versions.map((version) => (
                <TableRow key={version.id}>
                  <TableCell>v{version.versionNumber}</TableCell>
                  <TableCell className="break-all font-mono text-xs">{version.hash}</TableCell>
                  <TableCell className="font-mono text-xs text-muted-foreground">
                    {version.storagePath}
                  </TableCell>
                  <TableCell className="text-muted-foreground">
                    {version.createdAt.toISOString()}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
