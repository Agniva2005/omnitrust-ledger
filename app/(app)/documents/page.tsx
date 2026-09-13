import { FileText, Upload } from "lucide-react";
import Link from "next/link";
import { redirect } from "next/navigation";
import { PageHeader } from "@/components/page-header";
import { StatusBadge } from "@/components/status-badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
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
  const canUpload = can(actor.role, "document:upload");

  return (
    <div className="space-y-6">
      <PageHeader
        icon={FileText}
        title="Documents"
        description="Hashes below are SHA-256 of the uploaded bytes, computed on upload."
        actions={
          canUpload ? (
            <Button asChild>
              <Link href="/documents/upload">
                <Upload aria-hidden /> Upload document
              </Link>
            </Button>
          ) : null
        }
      />

      {documents.length === 0 ? (
        <div className="bg-grid rounded-xl border border-dashed px-4 py-16 text-center">
          <FileText aria-hidden className="mx-auto h-8 w-8 text-muted-foreground" />
          <p className="mt-3 text-sm text-muted-foreground">
            No documents yet.
            {canUpload ? " Upload one to get started." : ` Your role (${actor.role}) cannot upload.`}
          </p>
        </div>
      ) : (
        <Card className="overflow-hidden">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Filename</TableHead>
                <TableHead>Owner</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Versions</TableHead>
                <TableHead>SHA-256 (current)</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {documents.map((document) => (
                <TableRow key={document.id}>
                  <TableCell>
                    <Link href={`/documents/${document.id}`} className="group flex items-center gap-2.5 font-medium">
                      <span className="grid h-7 w-7 shrink-0 place-items-center rounded-md border bg-muted/40 text-muted-foreground group-hover:text-primary">
                        <FileText aria-hidden className="h-3.5 w-3.5" />
                      </span>
                      <span className="truncate group-hover:underline">{document.filename}</span>
                    </Link>
                  </TableCell>
                  <TableCell className="text-muted-foreground">{document.owner.email}</TableCell>
                  <TableCell>
                    <StatusBadge status={document.status} />
                  </TableCell>
                  <TableCell className="text-right tabular-nums text-muted-foreground">{document.versions.length}</TableCell>
                  <TableCell className="font-mono text-xs text-muted-foreground" title={document.currentHash}>
                    {document.currentHash.slice(0, 24)}...
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      )}
    </div>
  );
}
