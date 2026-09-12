import { notFound, redirect } from "next/navigation";
import { StatusBadge } from "@/components/status-badge";
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
import { getSession } from "@/lib/auth/session";
import { getDocument } from "@/lib/documents/service";
import { nextStates } from "@/lib/documents/lifecycle";
import { assertDocumentState } from "@/lib/documents/lifecycle";

export const dynamic = "force-dynamic";

export default async function DocumentDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const actor = await getSession();
  if (!actor) redirect("/login");

  const { id } = await params;
  const document = await getDocument(actor, id).catch((error) => {
    if (error instanceof NotFoundError) notFound();
    throw error;
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">{document.filename}</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Owned by {document.owner.email} &middot; {document.mimeType}
        </p>
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
