import { ArrowLeft, Blocks, Link2 } from "lucide-react";
import Link from "next/link";
import { notFound, redirect } from "next/navigation";
import { MerkleTreeView } from "@/app/(app)/anchoring/[batchId]/merkle-tree-view";
import { PageHeader } from "@/components/page-header";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { NotFoundError } from "@/lib/api";
import { batchDetail } from "@/lib/anchoring/service";
import { can } from "@/lib/auth/rbac";
import { getSession } from "@/lib/auth/session";
import { cn } from "@/lib/utils";

export const dynamic = "force-dynamic";

function Field({ label, value, mono = true }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="rounded-lg border bg-muted/30 p-3">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className={cn("mt-1 text-xs [overflow-wrap:anywhere]", mono && "font-mono")}>{value}</dd>
    </div>
  );
}

export default async function AnchorBatchPage({
  params,
  searchParams,
}: {
  params: Promise<{ batchId: string }>;
  searchParams: Promise<{ leaf?: string }>;
}) {
  const actor = await getSession();
  if (!actor) redirect("/login");
  if (!can(actor.role, "anchor:read")) redirect("/anchoring");

  const { batchId } = await params;
  const requested = Number.parseInt((await searchParams).leaf ?? "", 10);
  const detail = await batchDetail(actor, batchId, Number.isInteger(requested) ? requested : undefined).catch((error) => {
    if (error instanceof NotFoundError) notFound();
    throw error;
  });

  const { batch, leaves, selected, onChain } = detail;

  return (
    <div className="space-y-6">
      <PageHeader
        icon={Link2}
        eyebrow="Anchoring"
        title={`Batch of ${batch.leafCount} commitments`}
        description="The tree below is rebuilt from the stored commitments every time this page loads, and the root it produces is compared with the root that was sent to the chain. Select a leaf to see the audit path that proves it belongs to this tree."
        actions={
          <Button asChild variant="outline">
            <Link href="/anchoring">
              <ArrowLeft aria-hidden /> Back to anchoring
            </Link>
          </Button>
        }
      />

      <div className="grid items-start gap-6 2xl:grid-cols-[minmax(0,1fr)_28rem]">
        <div className="min-w-0 space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>The Merkle tree</CardTitle>
              <CardDescription>
                RFC 6962: a leaf is SHA-256(0x00 ‖ commitment), a node is SHA-256(0x01 ‖ left ‖ right). Only the root ever
                reaches the chain — never a document, a name or a key.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div
                className={cn(
                  "rounded-lg border p-3 text-sm",
                  detail.rootMatches ? "border-success/35 bg-success/[0.07] text-success" : "border-destructive/35 bg-destructive/[0.07] text-destructive",
                )}
              >
                {detail.rootMatches
                  ? "The stored commitments rebuild the recorded root exactly."
                  : `The stored commitments rebuild to ${detail.rebuiltRoot ?? "nothing"}, which is not the recorded root.`}
              </div>
              <MerkleTreeView tree={detail.tree} selected={selected?.index ?? null} labels={leaves} batchId={batch.id} />
              {selected === null && leaves.length > 0 && (
                <p className="text-xs text-muted-foreground">Select a leaf above to highlight its path to the root and show its inclusion proof.</p>
              )}
            </CardContent>
          </Card>

          {selected && (
            <Card>
              <CardHeader>
                <CardTitle>Inclusion proof for leaf {selected.index}</CardTitle>
                <CardDescription>
                  The sibling hashes a verifier needs, leaf-side first. With these and the root, anyone can confirm this
                  commitment is in the tree without seeing any of the others.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                <div
                  className={cn(
                    "rounded-lg border p-3 text-sm",
                    selected.verifies ? "border-success/35 bg-success/[0.07] text-success" : "border-destructive/35 bg-destructive/[0.07] text-destructive",
                  )}
                >
                  {selected.verifies ? "The proof verifies against the recorded root." : "The proof does not verify against the recorded root."}
                </div>
                <ol className="space-y-1.5">
                  {selected.proof.map((node, index) => (
                    <li key={node} className="flex items-center gap-2 rounded-lg border bg-warning/[0.06] px-3 py-1.5">
                      <span className="font-mono text-[10px] text-muted-foreground">step {index + 1}</span>
                      <code className="font-mono text-[11px] [overflow-wrap:anywhere]">{node}</code>
                    </li>
                  ))}
                  {selected.proof.length === 0 && <li className="text-xs text-muted-foreground">A single-leaf tree needs no proof: the leaf hash is the root.</li>}
                </ol>
              </CardContent>
            </Card>
          )}
        </div>

        <div className="min-w-0 space-y-6 2xl:sticky 2xl:top-20">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Blocks aria-hidden className="h-4 w-4 text-primary" /> On the chain
              </CardTitle>
              <CardDescription>Read back from the chain now, not from this application&apos;s own records.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              {onChain.reachable ? (
                <>
                  <div className={cn("rounded-lg border p-3 text-sm", onChain.event ? "border-success/35 bg-success/[0.07] text-success" : "border-warning/40 bg-warning/[0.07] text-warning")}>
                    {onChain.event ? `This root is recorded on chain in block ${onChain.event.blockNumber}.` : "This root is not recorded on the chain now answering — most likely a chain that has restarted."}
                  </div>
                  <dl className="grid gap-2">
                    <Field label="Contract address" value={batch.contractAddress} />
                    <Field label="Contract code matches" value={String(onChain.codeMatches)} mono={false} />
                    <Field label="Anchored at block" value={onChain.anchoredAtBlock} />
                    {onChain.event && <Field label="Event leaf count" value={String(onChain.event.leafCount)} />}
                    {onChain.event && <Field label="Block timestamp" value={onChain.event.timestamp.replace("T", " ").slice(0, 19)} />}
                    {onChain.event && <Field label="Transaction" value={onChain.event.txHash} />}
                  </dl>
                </>
              ) : (
                <div className="rounded-lg border border-warning/40 bg-warning/[0.07] p-3 text-sm text-warning">{onChain.reason}</div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>As recorded here</CardTitle>
              <CardDescription>What the application stored when it submitted the batch.</CardDescription>
            </CardHeader>
            <CardContent>
              <dl className="grid gap-2">
                <Field label="Merkle root" value={batch.root} />
                <Field label="Transaction" value={batch.txHash} />
                <Field label="Block" value={String(batch.blockNumber)} />
                <Field label="Block timestamp" value={batch.blockTimestamp.replace("T", " ").slice(0, 19)} />
                <Field label="Chain id" value={String(batch.chainId)} />
                <Field label="Anchored by" value={batch.createdBy ?? "—"} mono={false} />
              </dl>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
