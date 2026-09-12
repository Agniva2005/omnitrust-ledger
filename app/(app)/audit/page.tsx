import { redirect } from "next/navigation";
import { IntegrityChecker } from "@/app/(app)/audit/integrity-checker";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { auditEntryCount, listAuditEntries } from "@/lib/audit/log";
import { can } from "@/lib/auth/rbac";
import { getSession } from "@/lib/auth/session";

export const dynamic = "force-dynamic";

export default async function AuditPage() {
  const actor = await getSession();
  if (!actor) redirect("/login");

  const entries = await listAuditEntries(200);
  const total = await auditEntryCount();

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Audit log</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Append-only and hash-chained: each entry stores SHA-256 of the previous entry&apos;s hash
          concatenated with its own fields, so altering any row breaks the chain from that point on.
        </p>
      </div>

      {can(actor.role, "audit:verify") ? (
        <IntegrityChecker totalEntries={total} />
      ) : (
        <Card>
          <CardHeader>
            <CardTitle>Integrity check</CardTitle>
            <CardDescription>
              Role {actor.role} can read the log but not run the integrity check. Sign in as
              admin@demo or verifier@demo to run it.
            </CardDescription>
          </CardHeader>
        </Card>
      )}

      <div className="rounded-lg border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Seq</TableHead>
              <TableHead>Action</TableHead>
              <TableHead>Actor</TableHead>
              <TableHead>Target</TableHead>
              <TableHead>Details</TableHead>
              <TableHead>Entry hash</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {entries.length === 0 && (
              <TableRow>
                <TableCell colSpan={6} className="py-8 text-center text-sm text-muted-foreground">
                  No audit entries yet.
                </TableCell>
              </TableRow>
            )}
            {entries.map((entry) => (
              <TableRow key={entry.id}>
                <TableCell className="font-mono text-xs">{entry.seq}</TableCell>
                <TableCell>
                  <Badge
                    variant={
                      entry.action.includes("FAILED") || entry.action.includes("REVOKED")
                        ? "destructive"
                        : "secondary"
                    }
                  >
                    {entry.action}
                  </Badge>
                </TableCell>
                <TableCell className="text-muted-foreground">
                  {entry.actor?.email ?? "-"}
                </TableCell>
                <TableCell className="text-xs text-muted-foreground">
                  {entry.targetType}
                </TableCell>
                <TableCell className="max-w-md break-all font-mono text-xs text-muted-foreground">
                  {entry.metadataJson}
                </TableCell>
                <TableCell className="font-mono text-xs text-muted-foreground">
                  {entry.entryHash.slice(0, 12)}...
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
