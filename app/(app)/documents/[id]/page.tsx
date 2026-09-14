import { Download, FileCheck2, FileText, Fingerprint, GitBranch, Hash, TerminalSquare } from "lucide-react";
import Link from "next/link";
import { notFound, redirect } from "next/navigation";
import { SignPanel, type CertificateOption } from "@/app/(app)/documents/[id]/sign-panel";
import { CopyButton } from "@/components/copy-button";
import { PageHeader } from "@/components/page-header";
import { SecurityClassBadge } from "@/components/security-class-badge";
import { StatusBadge } from "@/components/status-badge";
import { Button, buttonVariants } from "@/components/ui/button";
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
import { cn } from "@/lib/utils";

export const dynamic = "force-dynamic";

const OPENSSL_COMMAND = "openssl cms -verify -binary -inform DER -in document.p7s -content document -CAfile ca.pem -out verified.bin";

function signatureSize(algorithm: string) {
  const metadata = orchestrator.lookup(algorithm);
  if (!metadata) return undefined;
  return metadata.signature.fixedBytes === null ? `≤ ${metadata.signature.maxBytes} B` : `${metadata.signature.fixedBytes} B`;
}

function SummaryTile({ icon: Icon, label, children }: { icon: typeof Hash; label: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0 rounded-xl border bg-card p-4 shadow-card">
      <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
        <Icon aria-hidden className="h-3.5 w-3.5" />
        {label}
      </div>
      <div className="mt-2 min-w-0 text-sm">{children}</div>
    </div>
  );
}

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
  const latestSignature = signatures.find((signature) => signature.documentVersion.versionNumber === latestVersion?.versionNumber);
  const latestSigned = Boolean(latestSignature);

  const certificates: CertificateOption[] = can(actor.role, "document:sign")
    ? (await signableCertificates(actor)).map((certificate) => ({
        id: certificate.id,
        algorithm: certificate.algorithm,
        displayName: orchestrator.displayName(certificate.algorithm),
        serialNumber: certificate.serialNumber,
        expiresAt: certificate.expiresAt.toISOString(),
        securityClass: orchestrator.lookup(certificate.algorithm)?.securityClass,
        signatureBytes: signatureSize(certificate.algorithm),
      }))
    : [];

  const all = orchestrator.describeAll();
  const listFormat = (items: string[], type: "conjunction" | "disjunction") => new Intl.ListFormat("en", { style: "long", type }).format(items);
  const opensslCapable = all.filter((metadata) => metadata.interoperability.opensslCms).map((metadata) => metadata.displayName);
  const opensslIncapable = all.filter((metadata) => !metadata.interoperability.opensslCms).map((metadata) => metadata.displayName);
  const legalNext = nextStates(assertDocumentState(document.status)).join(", ") || "none (terminal)";
  const exportLink = cn(buttonVariants({ variant: "outline", size: "sm" }), "h-7 px-2 text-xs");

  return (
    <div className="space-y-6">
      <PageHeader
        icon={FileText}
        eyebrow="Document"
        title={document.filename}
        description={`Owned by ${document.owner.email} · ${document.mimeType}`}
        actions={
          can(actor.role, "document:verify") ? (
            <Button asChild variant={signatures.length > 0 ? "default" : "outline"}>
              <Link href={`/documents/${document.id}/verify`}>
                <Fingerprint aria-hidden /> Verify
              </Link>
            </Button>
          ) : null
        }
      />

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <SummaryTile icon={GitBranch} label="Lifecycle state">
          <StatusBadge status={document.status} />
          <p className="mt-2 text-xs text-muted-foreground">
            Legal next states: <span className="font-mono">{legalNext}</span>
          </p>
          <p className="mt-1 text-[11px] text-muted-foreground">State machine from report Figure 4, enforced in lib/documents/lifecycle.ts.</p>
        </SummaryTile>
        <SummaryTile icon={Hash} label="Current SHA-256">
          <p className="font-mono text-xs [overflow-wrap:anywhere]">{document.currentHash}</p>
          <CopyButton value={document.currentHash} label="Copy hash" className="mt-2" />
        </SummaryTile>
        <SummaryTile icon={FileCheck2} label="Signature on the latest version">
          {latestSignature ? (
            <div className="space-y-1.5">
              <div className="font-medium">{orchestrator.displayName(latestSignature.algorithm)}</div>
              {orchestrator.lookup(latestSignature.algorithm) && <SecurityClassBadge securityClass={orchestrator.lookup(latestSignature.algorithm)!.securityClass} />}
              <p className="text-xs text-muted-foreground">{latestSignature.signatureBytes.length} bytes, by {latestSignature.signedBy.email}</p>
            </div>
          ) : (
            <p className="text-muted-foreground">Not yet signed.</p>
          )}
        </SummaryTile>
        <SummaryTile icon={GitBranch} label="Versions">
          <div className="text-2xl font-semibold tabular-nums">{document.versions.length}</div>
          <p className="text-xs text-muted-foreground">Latest is v{latestVersion?.versionNumber}; each version keeps its own hash and at most one signature.</p>
        </SummaryTile>
      </div>

      {can(actor.role, "document:sign") && (
        <Card>
          <CardHeader>
            <CardTitle>Sign</CardTitle>
            <CardDescription>
              {latestSigned
                ? `Version ${latestVersion?.versionNumber} is already signed. One signature per version keeps verification unambiguous about which hash was signed; upload a new version to sign again.`
                : "The orchestrator signs the 32 raw bytes of the current version's SHA-256."}
            </CardDescription>
          </CardHeader>
          {!latestSigned && (
            <CardContent>
              <SignPanel documentId={document.id} certificates={certificates} />
            </CardContent>
          )}
        </Card>
      )}

      <Card className="overflow-hidden">
        <CardHeader>
          <CardTitle>Signatures</CardTitle>
          <CardDescription>Each signature is bound to one document version and one certificate.</CardDescription>
        </CardHeader>
        {signatures.length === 0 ? (
          <CardContent>
            <p className="rounded-lg border border-dashed px-4 py-6 text-center text-sm text-muted-foreground">Not yet signed.</p>
          </CardContent>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="pl-5">Version</TableHead>
                <TableHead>Algorithm</TableHead>
                <TableHead className="text-right">Size</TableHead>
                <TableHead>Certificate</TableHead>
                <TableHead>Signer</TableHead>
                <TableHead>Signed at (UTC)</TableHead>
                <TableHead className="pr-5">Export</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {signatures.map((signature) => {
                const version = signature.documentVersion.versionNumber;
                const metadata = orchestrator.lookup(signature.algorithm);
                return (
                  <TableRow key={signature.id}>
                    <TableCell className="pl-5 font-mono text-xs">v{version}</TableCell>
                    <TableCell>
                      <div className="whitespace-nowrap font-medium">{orchestrator.displayName(signature.algorithm)}</div>
                      {metadata && (
                        <div className="mt-1">
                          <SecurityClassBadge securityClass={metadata.securityClass} />
                        </div>
                      )}
                    </TableCell>
                    <TableCell className="whitespace-nowrap text-right tabular-nums text-muted-foreground">{signature.signatureBytes.length} bytes</TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      <Link href={`/certificates/${signature.certificate.id}`} className="hover:text-foreground hover:underline" title={signature.certificate.serialNumber}>
                        {signature.certificate.serialNumber.slice(0, 12)}...
                      </Link>{" "}
                      {signature.certificate.status !== "ACTIVE" && <StatusBadge status={signature.certificate.status} />}
                    </TableCell>
                    <TableCell className="text-muted-foreground">{signature.signedBy.email}</TableCell>
                    <TableCell className="whitespace-nowrap font-mono text-xs text-muted-foreground">
                      {signature.signedAt.toISOString().replace("T", " ").slice(0, 19)}
                    </TableCell>
                    <TableCell className="pr-5">
                      <div className="flex flex-wrap gap-1.5">
                        {signature.cmsSignature ? (
                          <a className={exportLink} href={`/api/documents/${document.id}/export?part=cms&version=${version}`}>
                            <Download aria-hidden /> CMS (.p7s)
                          </a>
                        ) : (
                          <span className="text-xs text-muted-foreground">no CMS</span>
                        )}
                        <a className={exportLink} href={`/api/documents/${document.id}/export?part=content&version=${version}`}>
                          <Download aria-hidden /> Document
                        </a>
                        <a className={exportLink} href={`/api/documents/${document.id}/export?part=certificate&version=${version}`}>
                          <Download aria-hidden /> Certificate
                        </a>
                      </div>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        )}
      </Card>

      {signatures.some((signature) => signature.cmsSignature) && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <TerminalSquare aria-hidden className="h-4 w-4 text-primary" /> Verify outside this app
            </CardTitle>
            <CardDescription>
              The CMS export is a standard detached signature (RFC 5652) carrying the signer&apos;s and the CA&apos;s certificates and a time-stamp over its
              signature value. Download it, the document and the{" "}
              <a className="font-medium text-primary underline-offset-2 hover:underline" href="/api/pki/ca?format=pem">
                CA certificate
              </a>
              , then run:
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            <div className="flex items-start gap-2 rounded-lg border bg-muted/50 p-3">
              <pre className="min-w-0 flex-1 overflow-x-auto font-mono text-xs">{OPENSSL_COMMAND}</pre>
              <CopyButton value={OPENSSL_COMMAND} label="Copy command" />
            </div>
            <p className="text-muted-foreground">
              Checked with the OpenSSL 3.2.4 and 3.4.0 command-line tools for {listFormat(opensslCapable, "conjunction")}. Those tools cannot process{" "}
              {listFormat(opensslIncapable, "disjunction")} CMS signatures, so those are checked in the test suite against independent implementations instead.
              This is a demo CA: a successful check means the file is consistent, not that anyone outside this installation trusts the signer.
            </p>
          </CardContent>
        </Card>
      )}

      <Card className="overflow-hidden">
        <CardHeader>
          <CardTitle>Versions</CardTitle>
          <CardDescription>Each version records the hash of the bytes stored for it. Blobs are encrypted at rest with AES-256-GCM.</CardDescription>
        </CardHeader>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="pl-5">Version</TableHead>
              <TableHead>SHA-256</TableHead>
              <TableHead>Signature</TableHead>
              <TableHead>Stored at</TableHead>
              <TableHead className="pr-5">Created (UTC)</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {document.versions.map((version) => {
              const signature = signatures.find((candidate) => candidate.documentVersion.versionNumber === version.versionNumber);
              return (
                <TableRow key={version.id}>
                  <TableCell className="pl-5 font-mono text-xs">v{version.versionNumber}</TableCell>
                  <TableCell className="max-w-[18rem] font-mono text-xs [overflow-wrap:anywhere]">{version.hash}</TableCell>
                  <TableCell className="text-xs">
                    {signature ? (
                      `${orchestrator.displayName(signature.algorithm)} by ${signature.signedBy.email}`
                    ) : (
                      <span className="text-muted-foreground">unsigned</span>
                    )}
                  </TableCell>
                  <TableCell className="font-mono text-xs text-muted-foreground">{version.storagePath}</TableCell>
                  <TableCell className="whitespace-nowrap pr-5 font-mono text-xs text-muted-foreground">
                    {version.createdAt.toISOString().replace("T", " ").slice(0, 19)}
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </Card>
    </div>
  );
}
