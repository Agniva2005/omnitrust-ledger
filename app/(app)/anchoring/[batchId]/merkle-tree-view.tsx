import Link from "next/link";
import type { MerkleNode } from "@/lib/crypto/merkle";
import { cn } from "@/lib/utils";

export type LeafLabel = { index: number; kind: string; label: string };

/** Leaf indices under a node, so the path from a chosen leaf up to the root can be highlighted. */
function covers(node: MerkleNode, index: number): boolean {
  if (node.kind === "leaf") return node.index === index;
  return covers(node.left, index) || covers(node.right, index);
}

function Hash({ value, tone }: { value: string; tone: "path" | "sibling" | "plain" }) {
  return (
    <code
      className={cn(
        "rounded px-1.5 py-0.5 font-mono text-[11px]",
        tone === "path" && "bg-primary/15 text-foreground",
        tone === "sibling" && "bg-warning/15 text-foreground",
        tone === "plain" && "bg-muted text-muted-foreground",
      )}
      title={value}
    >
      {value.slice(0, 16)}…
    </code>
  );
}

function Node({
  node,
  selected,
  labels,
  batchId,
  depth,
  onPath,
}: {
  node: MerkleNode;
  selected: number | null;
  labels: Map<number, LeafLabel>;
  batchId: string;
  depth: number;
  onPath: boolean;
}) {
  const isOnPath = selected !== null && covers(node, selected);
  // A sibling of the path is exactly what the inclusion proof hands the verifier.
  const isProofSibling = !isOnPath && onPath;

  if (node.kind === "leaf") {
    const label = labels.get(node.index);
    const chosen = selected === node.index;
    return (
      <li className="relative">
        <div className={cn("rounded-lg border px-3 py-2", chosen ? "border-primary bg-primary/10" : isProofSibling ? "border-warning/50 bg-warning/[0.06]" : "bg-card")}>
          <div className="flex flex-wrap items-center gap-2">
            <span className="rounded bg-muted px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">leaf {node.index}</span>
            <Link href={`/anchoring/${batchId}?leaf=${node.index}`} className="text-xs font-medium hover:underline">
              {label?.label ?? "Commitment"}
            </Link>
          </div>
          <div className="mt-1">
            <Hash value={node.hash} tone={chosen ? "path" : isProofSibling ? "sibling" : "plain"} />
          </div>
        </div>
      </li>
    );
  }

  return (
    <li className="relative">
      <div className={cn("inline-flex items-center gap-2 rounded-lg border px-3 py-1.5", isOnPath ? "border-primary/50 bg-primary/[0.06]" : isProofSibling ? "border-warning/50 bg-warning/[0.06]" : "bg-muted/30")}>
        <span className="text-[10px] uppercase tracking-wide text-muted-foreground">{depth === 0 ? "root" : "node"}</span>
        <Hash value={node.hash} tone={isOnPath ? "path" : isProofSibling ? "sibling" : "plain"} />
      </div>
      <ul className="mt-2 space-y-2 border-l pl-4">
        <Node node={node.left} selected={selected} labels={labels} batchId={batchId} depth={depth + 1} onPath={isOnPath} />
        <Node node={node.right} selected={selected} labels={labels} batchId={batchId} depth={depth + 1} onPath={isOnPath} />
      </ul>
    </li>
  );
}

export function MerkleTreeView({
  tree,
  selected,
  labels,
  batchId,
}: {
  tree: MerkleNode | null;
  selected: number | null;
  labels: LeafLabel[];
  batchId: string;
}) {
  if (!tree) {
    return <p className="rounded-lg border border-dashed px-4 py-6 text-center text-sm text-muted-foreground">This batch&apos;s leaves are not contiguous, so the tree cannot be rebuilt from them.</p>;
  }
  const map = new Map(labels.map((leaf) => [leaf.index, leaf]));
  return (
    <div className="overflow-x-auto">
      <ul className="min-w-fit space-y-2">
        <Node node={tree} selected={selected} labels={map} batchId={batchId} depth={0} onPath={false} />
      </ul>
    </div>
  );
}
