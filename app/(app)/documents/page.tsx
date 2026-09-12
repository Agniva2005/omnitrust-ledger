import Link from "next/link";
import { redirect } from "next/navigation";
import { StatusBadge } from "@/components/status-badge";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { can } from "@/lib/auth/rbac";
import { getSession } from "@/lib/auth/session";
import { listDocuments } from "@/lib/documents/service";

export const dynamic = "force-dynamic";

export default async function DocumentsPage() {
  const actor = await getSession();
  if (!actor) redirect("/login");

  const documents = await listDocuments(actor);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Documents</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Hashes below are SHA-256 of the uploaded bytes, computed on upload.
          </p>
        </div>
        {can(actor.role, "document:upload") && (
          <Button asChild>
            <Link href="/documents/upload">Upload document</Link>
          </Button>
        )}
      </div>

      {documents.length === 0 ? (
        <p className="rounded-lg border border-dashed px-4 py-10 text-center text-sm text-muted-foreground">
          No documents yet.
          {can(actor.role, "document:upload")
            ? " Upload one to get started."
            : ` Your role (${actor.role}) cannot upload.`}
        </p>
      ) : (
        <div className="rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Filename</TableHead>
                <TableHead>Owner</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Versions</TableHead>
                <TableHead>SHA-256 (current)</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {documents.map((document) => (
                <TableRow key={document.id}>
                  <TableCell>
                    <Link href={`/documents/${document.id}`} className="font-medium hover:underline">
                      {document.filename}
                    </Link>
                  </TableCell>
                  <TableCell className="text-muted-foreground">{document.owner.email}</TableCell>
                  <TableCell>
                    <StatusBadge status={document.status} />
                  </TableCell>
                  <TableCell className="text-muted-foreground">{document.versions.length}</TableCell>
                  <TableCell className="font-mono text-xs text-muted-foreground">
                    {document.currentHash.slice(0, 24)}...
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  );
}
