import { Download, FileCheck2, FilePlus2, FileText, Fingerprint, FlaskConical, GitBranch, Hash, Package, Share2, TerminalSquare } from "lucide-react";
import Link from "next/link";
import { notFound, redirect } from "next/navigation";
import { HistoryTimeline } from "@/app/(app)/documents/[id]/history-timeline";
import { NewVersionPanel } from "@/app/(app)/documents/[id]/new-version-panel";
import { SharePanel } from "@/app/(app)/documents/[id]/share-panel";
import { SignPanel, type CertificateOption } from "@/app/(app)/documents/[id]/sign-panel";
import { TamperPanel } from "@/app/(app)/documents/[id]/tamper-panel";
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
import { documentArtifacts } from "@/lib/documents/artifacts";
import { tamperState } from "@/lib/documents/demo-tamper";
import { documentHistory } from "@/lib/documents/history";
import { listShares } from "@/lib/documents/sharing";
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
  const hasCms = signatures.some((signature) => signature.cmsSignature);

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

  // Reads and hashes the stored blob, so it is computed only for the role that can act on it.
  const tamper = can(actor.role, "demo:tamper") ? await tamperState(document.id) : null;

  const history = await documentHistory(document.id);
  const artifacts = await documentArtifacts(document.id);
  const shares = await listShares(actor, document.id);

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

      {/* On a wide monitor the sign form and the offline-verification recipe sit side by side. */}
      <div className={cn("grid items-start gap-6", can(actor.role, "document:sign") && hasCms && "3xl:grid-cols-2")}>
      {can(actor.role, "document:sign") && (
        <Card className="min-w-0">
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

      {hasCms && (
        <Card className="min-w-0">
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
            <p className="max-w-4xl text-muted-foreground">
              Checked with the OpenSSL 3.2.4 and 3.4.0 command-line tools for {listFormat(opensslCapable, "conjunction")}. Those tools cannot process{" "}
              {listFormat(opensslIncapable, "disjunction")} CMS signatures, so those are checked in the test suite against independent implementations instead.
              This is a demo CA: a successful check means the file is consistent, not that anyone outside this installation trusts the signer.
            </p>
          </CardContent>
        </Card>
      )}
      </div>

      <div className={cn("grid items-start gap-6", can(actor.role, "document:upload") && tamper && "3xl:grid-cols-2")}>
        {can(actor.role, "document:upload") && latestVersion && (
          <Card className="min-w-0">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <FilePlus2 aria-hidden className="h-4 w-4 text-primary" /> Upload a new version
              </CardTitle>
              <CardDescription>
                A signed version is immutable. Uploading edited content creates v{(latestVersion.versionNumber ?? 0) + 1} with its own hash,
                leaving v{latestVersion.versionNumber} and its signature exactly as they were — so the two can be compared, and the new
                one signed in its own right.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <NewVersionPanel
                documentId={document.id}
                currentVersion={latestVersion.versionNumber}
                currentHash={latestVersion.hash}
              />
            </CardContent>
          </Card>
        )}

        {tamper && (
          <Card className="min-w-0 border-dashed">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <FlaskConical aria-hidden className="h-4 w-4 text-primary" /> Tamper with this document
              </CardTitle>
              <CardDescription>
                Demonstration only, and available to ADMIN alone. These perform the alteration an attacker with storage or
                database access would perform, then leave verification to notice it. No verdict is faked: the bytes really
                change, and the verifier really recomputes.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <TamperPanel documentId={document.id} hasSignature={latestSigned} initialState={tamper} />
            </CardContent>
          </Card>
        )}
      </div>

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
                        <a className={cn(buttonVariants({ variant: "default", size: "sm" }), "h-7 px-2 text-xs")} href={`/api/documents/${document.id}/evidence?version=${version}`}>
                          <Package aria-hidden /> Evidence pack
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

      {latestSigned && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Share2 aria-hidden className="h-4 w-4 text-primary" /> Share for verification
            </CardTitle>
            <CardDescription>
              Give someone without an account a link that verifies this version and nothing else. They see the same ten
              checks and can take the evidence away; you can withdraw it at any moment, and every use is on the record.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <SharePanel
              documentId={document.id}
              versionNumber={latestVersion.versionNumber}
              initialShares={shares}
              canShare={can(actor.role, "document:share") && document.owner.email === actor.email}
            />
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle>The bytes themselves</CardTitle>
          <CardDescription>
            A signature is a column in the database and a stored document is an encrypted file, so neither is visible
            anywhere else. Both are shown here as they are stored — which is also how you watch them change when something
            is altered.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-5">
          {artifacts.signatures.length > 0 && (
            <div className="space-y-2">
              <h3 className="text-sm font-medium">Signature bytes</h3>
              {artifacts.signatures.map((signature) => (
                <div key={`${signature.versionNumber}-${signature.algorithm}`} className="rounded-lg border bg-muted/20 p-3">
                  <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                    <span className="font-mono">v{signature.versionNumber}</span>
                    <span>{orchestrator.displayName(signature.algorithm)}</span>
                    <span className="tabular-nums">{signature.byteLength} bytes</span>
                    {signature.timestampedAt && <span>· time-stamped {signature.timestampedAt.replace("T", " ").slice(0, 19)}</span>}
                    {signature.timestampTokenBytes !== null && <span>· token {signature.timestampTokenBytes} B</span>}
                    {signature.cmsBytes !== null && <span>· CMS {signature.cmsBytes} B</span>}
                  </div>
                  <p className="mt-2 break-all font-mono text-[11px] leading-relaxed">{signature.hex}</p>
                  <CopyButton value={signature.hex} label="Copy signature hex" className="mt-2" />
                </div>
              ))}
            </div>
          )}

          <div className="space-y-2">
            <h3 className="text-sm font-medium">Stored file, as written to disk</h3>
            {artifacts.blobs.map((blob) => (
              <div key={blob.versionNumber} className="rounded-lg border bg-muted/20 p-3">
                <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                  <span className="font-mono">v{blob.versionNumber}</span>
                  <span className="font-mono [overflow-wrap:anywhere]">{blob.storagePath}</span>
                  {blob.unreadable === null && <span className="tabular-nums">{blob.fileBytes.toLocaleString()} bytes</span>}
                </div>
                {blob.unreadable ? (
                  <p className="mt-2 text-xs text-destructive">{blob.unreadable}</p>
                ) : (
                  <dl className="mt-2 space-y-1.5 font-mono text-[11px]">
                    <div className="flex flex-wrap gap-2">
                      <dt className="w-24 shrink-0 text-muted-foreground">IV (12 B)</dt>
                      <dd className="break-all">{blob.iv}</dd>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      <dt className="w-24 shrink-0 text-muted-foreground">GCM tag (16 B)</dt>
                      <dd className="break-all">{blob.tag}</dd>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      <dt className="w-24 shrink-0 text-muted-foreground">ciphertext</dt>
                      <dd className="break-all">
                        {blob.ciphertextHead}… <span className="text-muted-foreground">({blob.ciphertextBytes.toLocaleString()} bytes)</span>
                      </dd>
                    </div>
                  </dl>
                )}
              </div>
            ))}
            <p className="text-xs text-muted-foreground">
              The tag authenticates the ciphertext: change any byte of the file and decryption refuses it rather than
              returning different plaintext.
            </p>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>History</CardTitle>
          <CardDescription>
            Every line is an entry in the hash-chained audit log, shown with the sequence number and hash it has there. Verify
            the log on the Audit log page and these are the records it walks.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <HistoryTimeline events={history} />
        </CardContent>
      </Card>

      <Card className="overflow-hidden">
        <CardHeader>
          <CardTitle>Versions</CardTitle>
          <CardDescription>
            Each version records the hash of the bytes stored for it, so any two versions can be compared by their
            fingerprints alone. Blobs are encrypted at rest with AES-256-GCM.
          </CardDescription>
        </CardHeader>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="pl-5">Version</TableHead>
              <TableHead>SHA-256</TableHead>
              <TableHead>Compared with previous</TableHead>
              <TableHead>Signature</TableHead>
              <TableHead>Created (UTC)</TableHead>
              <TableHead className="pr-5" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {document.versions.map((version) => {
              const signature = signatures.find((candidate) => candidate.documentVersion.versionNumber === version.versionNumber);
              const previous = document.versions.find((candidate) => candidate.versionNumber === version.versionNumber - 1);
              return (
                <TableRow key={version.id}>
                  <TableCell className="pl-5 align-top">
                    <div className="font-mono text-xs">v{version.versionNumber}</div>
                    <div className="mt-1 font-mono text-[11px] text-muted-foreground [overflow-wrap:anywhere]">{version.storagePath}</div>
                  </TableCell>
                  <TableCell className="max-w-[18rem] align-top font-mono text-xs [overflow-wrap:anywhere]">{version.hash}</TableCell>
                  <TableCell className="align-top text-xs">
                    {previous ? (
                      <>
                        <span className="font-medium text-destructive">content changed</span>
                        <div className="mt-1 text-muted-foreground">
                          v{previous.versionNumber} hashed to{" "}
                          <span className="font-mono [overflow-wrap:anywhere]">{previous.hash.slice(0, 16)}…</span>
                        </div>
                      </>
                    ) : (
                      <span className="text-muted-foreground">first version</span>
                    )}
                  </TableCell>
                  <TableCell className="align-top text-xs">
                    {signature ? (
                      `${orchestrator.displayName(signature.algorithm)} by ${signature.signedBy.email}`
                    ) : (
                      <span className="text-muted-foreground">unsigned</span>
                    )}
                  </TableCell>
                  <TableCell className="whitespace-nowrap align-top font-mono text-xs text-muted-foreground">
                    {version.createdAt.toISOString().replace("T", " ").slice(0, 19)}
                  </TableCell>
                  <TableCell className="pr-5 align-top">
                    {signature && can(actor.role, "document:verify") && (
                      <Link className={exportLink} href={`/documents/${document.id}/verify?version=${version.versionNumber}`}>
                        <Fingerprint aria-hidden /> Verify
                      </Link>
                    )}
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
