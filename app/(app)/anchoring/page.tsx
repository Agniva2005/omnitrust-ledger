import { redirect } from "next/navigation";
import { AnchorButton } from "@/app/(app)/anchoring/anchor-button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { anchoringOverview } from "@/lib/anchoring/service";
import { can } from "@/lib/auth/rbac";
import { getSession } from "@/lib/auth/session";

export const dynamic = "force-dynamic";

export default async function AnchoringPage() {
  const actor = await getSession();
  if (!actor) redirect("/login");

  const overview = await anchoringOverview(actor);
  const { chain } = overview;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Blockchain anchoring</h1>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
          Signatures and signed audit checkpoints are reduced to 32-byte SHA-256 commitments, batched
          into an RFC 6962 Merkle tree, and only the tree&apos;s root is recorded on a local
          development chain. No document, personal data or key goes on chain.
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Local chain</CardTitle>
            <CardDescription className="break-all font-mono text-xs">{chain.rpcUrl}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2 text-sm">
            {chain.reachable ? (
              <>
                <Badge variant="success">REACHABLE</Badge>
                <div>
                  Chain {chain.chainId}, block {chain.blockNumber}
                </div>
                <div className="break-all font-mono text-xs text-muted-foreground">genesis {chain.genesisHash}</div>
                <div className="text-muted-foreground">
                  {chain.contract
                    ? `Anchor contract ${chain.contract.address} (${chain.contract.codeMatches ? "code matches contracts/OmniTrustAnchor.sol" : "CODE DOES NOT MATCH"})`
                    : "The anchor contract will be deployed on the first anchoring."}
                </div>
              </>
            ) : (
              <>
                <Badge variant="outline">UNAVAILABLE</Badge>
                <p className="text-muted-foreground">{chain.reason}</p>
              </>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Pending</CardTitle>
            <CardDescription>
              {overview.pending.signatures} signature{overview.pending.signatures === 1 ? "" : "s"} and{" "}
              {overview.pending.auditCheckpoints} audit checkpoint{overview.pending.auditCheckpoints === 1 ? "" : "s"} not yet anchored.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {can(actor.role, "anchor:create") ? (
              <AnchorButton pending={overview.pending.total} chainReachable={chain.reachable} />
            ) : (
              <p className="text-sm text-muted-foreground">Only an admin can anchor.</p>
            )}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>What an anchor does and does not show</CardTitle>
        </CardHeader>
        <CardContent>
          <ul className="list-disc space-y-1 pl-5 text-sm text-muted-foreground">
            <li>It shows that a commitment was part of a tree whose root was recorded in a given block of this chain instance.</li>
            <li>It does not identify anyone. Who signed is established by the PKI, not by the chain.</li>
            <li>
              The development chain is in-memory. Restarting it discards every anchor, and verification then reports
              UNAVAILABLE rather than a result.
            </li>
            <li>Transactions come from the node&apos;s public development account; the app holds no chain key. A public chain would need real key custody, which is not implemented.</li>
          </ul>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Anchored batches</CardTitle>
        </CardHeader>
        <CardContent>
          {overview.batches.length === 0 ? (
            <p className="text-sm text-muted-foreground">Nothing has been anchored yet.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Merkle root</TableHead>
                  <TableHead>Leaves</TableHead>
                  <TableHead>Block</TableHead>
                  <TableHead>Anchored at</TableHead>
                  <TableHead>Transaction</TableHead>
                  <TableHead>Chain</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {overview.batches.map((batch) => (
                  <TableRow key={batch.id}>
                    <TableCell className="font-mono text-xs">{batch.root.slice(0, 16)}...</TableCell>
                    <TableCell>{batch.leafCount}</TableCell>
                    <TableCell>{batch.blockNumber}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">{batch.blockTimestamp}</TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">{batch.txHash.slice(0, 14)}...</TableCell>
                    <TableCell>
                      <Badge variant={batch.onCurrentChain ? "secondary" : "outline"}>
                        {batch.onCurrentChain ? "current" : "chain gone"}
                      </Badge>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
