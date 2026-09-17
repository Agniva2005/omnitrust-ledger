// Anchoring layer: batches commitments into an RFC 6962 Merkle tree and records the root on a
// local development chain.
//
// What is anchored: 32-byte SHA-256 commitments to signatures and to signed audit checkpoints,
// computed from identifiers and hashes only. The leaves stay in this database; only the root
// and the leaf count go on chain, in a contract that stores nothing else. No document, personal
// data or key is ever sent to the chain.
//
// What an anchor shows: that a commitment was part of a tree whose root was recorded in a given
// block of this chain instance. It does not identify anyone (identity is the PKI's job). And it
// shows nothing once that chain instance is gone: the development chain is in-memory, so
// restarting it discards every anchor, and verification then reports UNAVAILABLE.
import type { AnchorContract } from "@prisma/client";
import type { Address, Hex } from "viem";
import {
  AnchorRejectedError,
  ChainUnavailableError,
  anchorRpcUrl,
  chainInfo,
  contractCodeMatches,
  deployAnchorContract,
  readAnchor,
  submitRoot,
} from "@/lib/anchoring/chain";
import { ConflictError, NotFoundError } from "@/lib/api";
import { appendAuditEntry } from "@/lib/audit/log";
import { requireCapability, type Actor } from "@/lib/auth/rbac";
import { sha256Hex } from "@/lib/crypto/hash";
import { merkleInclusionProof, merkleRoot, merkleTree, verifyMerkleInclusion, type MerkleNode } from "@/lib/crypto/merkle";
import { prisma } from "@/lib/db";

export const ANCHOR_KINDS = ["SIGNATURE", "AUDIT_CHECKPOINT"] as const;
export type AnchorKind = (typeof ANCHOR_KINDS)[number];

export function isAnchorKind(value: unknown): value is AnchorKind {
  return typeof value === "string" && (ANCHOR_KINDS as readonly string[]).includes(value);
}

const LEAF_FORMAT = "omnitrust-anchor-leaf/1";

const isUniqueViolation = (error: unknown) => (error as { code?: unknown } | null)?.code === "P2002";

/** The commitment for an item as it is stored now, or null if the item no longer exists. */
export async function commitmentFor(kind: AnchorKind, targetId: string): Promise<string | null> {
  if (kind === "SIGNATURE") {
    const signature = await prisma.signature.findUnique({
      where: { id: targetId },
      include: {
        documentVersion: { select: { hash: true } },
        certificate: { select: { serialNumber: true } },
      },
    });
    if (!signature) return null;
    return sha256Hex(
      [
        LEAF_FORMAT,
        "signature",
        signature.id,
        signature.documentVersion.hash,
        sha256Hex(signature.signatureBytes),
        signature.certificate.serialNumber,
        signature.algorithm,
      ].join("\n"),
    );
  }

  const checkpoint = await prisma.auditCheckpoint.findUnique({ where: { id: targetId } });
  if (!checkpoint) return null;
  return sha256Hex([LEAF_FORMAT, "audit-checkpoint", checkpoint.id, String(checkpoint.seq), checkpoint.checkpointHash].join("\n"));
}

export type PendingCommitment = { kind: AnchorKind; targetId: string; commitment: string };

/** Signatures and audit checkpoints not yet in any anchored batch, oldest first. */
export async function pendingCommitments(): Promise<PendingCommitment[]> {
  const anchored = new Set(
    (await prisma.anchorLeaf.findMany({ select: { kind: true, targetId: true } })).map(
      (leaf) => `${leaf.kind}:${leaf.targetId}`,
    ),
  );
  const signatures = await prisma.signature.findMany({ orderBy: { signedAt: "asc" }, select: { id: true } });
  const checkpoints = await prisma.auditCheckpoint.findMany({ orderBy: { seq: "asc" }, select: { id: true } });

  const items: { kind: AnchorKind; targetId: string }[] = [
    ...signatures.map((signature) => ({ kind: "SIGNATURE" as const, targetId: signature.id })),
    ...checkpoints.map((checkpoint) => ({ kind: "AUDIT_CHECKPOINT" as const, targetId: checkpoint.id })),
  ].filter((item) => !anchored.has(`${item.kind}:${item.targetId}`));

  const pending: PendingCommitment[] = [];
  for (const item of items) {
    const commitment = await commitmentFor(item.kind, item.targetId);
    if (commitment) pending.push({ ...item, commitment });
  }
  return pending;
}

/** The anchor contract on the chain currently answering, deploying it on first use. */
export async function ensureAnchorContract(actorUserId: string | null): Promise<AnchorContract> {
  const info = await chainInfo();
  const where = { chainId_genesisHash: { chainId: info.chainId, genesisHash: info.genesisHash } };
  const existing = await prisma.anchorContract.findUnique({ where });
  if (existing) {
    if (await contractCodeMatches(existing.address as Address)) return existing;
    throw new AnchorRejectedError(
      `The address recorded for the anchor contract on this chain (${existing.address}) does not hold the OmniTrust anchor contract`,
    );
  }

  const deployed = await deployAnchorContract();
  let contract: AnchorContract;
  try {
    contract = await prisma.anchorContract.create({
      data: {
        chainId: deployed.chainId,
        genesisHash: deployed.genesisHash,
        address: deployed.address,
        deployTxHash: deployed.txHash,
        ownerAddress: deployed.owner,
      },
    });
  } catch (error) {
    // Another request deployed at the same moment; use the contract it recorded.
    if (isUniqueViolation(error)) return prisma.anchorContract.findUniqueOrThrow({ where });
    throw error;
  }

  await appendAuditEntry({
    actorUserId,
    action: "ANCHOR_CONTRACT_DEPLOYED",
    targetType: "AnchorContract",
    targetId: contract.id,
    metadata: {
      chainId: contract.chainId,
      address: contract.address,
      txHash: contract.deployTxHash,
      genesisHash: contract.genesisHash,
    },
  });
  return contract;
}

/** Anchors every pending commitment as one Merkle root in one transaction. */
export async function anchorPending(actor: Actor) {
  requireCapability(actor, "anchor:create");
  const contract = await ensureAnchorContract(actor.userId);

  const pending = await pendingCommitments();
  if (pending.length === 0) {
    throw new ConflictError("There is nothing new to anchor: every signature and audit checkpoint is already in an anchored batch");
  }

  const root = merkleRoot(pending.map((item) => Buffer.from(item.commitment, "hex"))).toString("hex");
  const submitted = await submitRoot(contract.address as Address, `0x${root}`, pending.length);

  let batch;
  try {
    batch = await prisma.anchorBatch.create({
      data: {
        contractId: contract.id,
        root,
        leafCount: pending.length,
        txHash: submitted.txHash,
        blockNumber: Number(submitted.blockNumber),
        blockTimestamp: submitted.blockTimestamp,
        createdByUserId: actor.userId,
        leaves: {
          create: pending.map((item, index) => ({
            index,
            kind: item.kind,
            targetId: item.targetId,
            commitment: item.commitment,
          })),
        },
      },
      include: { leaves: true },
    });
  } catch (error) {
    if (isUniqueViolation(error)) {
      throw new ConflictError(
        "Another batch anchored some of these items at the same moment. The root this attempt recorded on chain is unused.",
      );
    }
    throw error;
  }

  await appendAuditEntry({
    actorUserId: actor.userId,
    action: "ANCHOR_BATCH_CREATED",
    targetType: "AnchorBatch",
    targetId: batch.id,
    metadata: {
      root,
      leafCount: batch.leafCount,
      signatures: pending.filter((item) => item.kind === "SIGNATURE").length,
      auditCheckpoints: pending.filter((item) => item.kind === "AUDIT_CHECKPOINT").length,
      txHash: batch.txHash,
      blockNumber: batch.blockNumber,
      chainId: contract.chainId,
      contractAddress: contract.address,
    },
  });
  return batch;
}

export type AnchorCheck = { step: string; status: "PASS" | "FAIL" | "UNAVAILABLE"; detail?: string };

export type AnchorVerification = {
  /** VALID: anchored and confirmed on chain. INVALID: evidence against. UNAVAILABLE: the chain cannot be consulted. NOT_ANCHORED: not in any batch yet. */
  status: "VALID" | "INVALID" | "UNAVAILABLE" | "NOT_ANCHORED";
  kind: AnchorKind;
  targetId: string;
  leafIndex: number | null;
  batch: {
    id: string;
    root: string;
    leafCount: number;
    txHash: string;
    blockNumber: number;
    blockTimestamp: string;
    chainId: number;
    contractAddress: string;
  } | null;
  proof: string[];
  anchoredAt: string | null;
  explanation: string;
  checks: AnchorCheck[];
};

export async function verifyAnchor(kind: AnchorKind, targetId: string): Promise<AnchorVerification> {
  const checks: AnchorCheck[] = [];
  const result: Omit<AnchorVerification, "status" | "explanation" | "checks"> = {
    kind,
    targetId,
    leafIndex: null,
    batch: null,
    proof: [],
    anchoredAt: null,
  };
  const check = (step: string, status: AnchorCheck["status"], detail?: string) => {
    checks.push({ step, status, detail });
    return status === "PASS";
  };
  const conclude = (status: AnchorVerification["status"], explanation: string): AnchorVerification => ({
    status,
    ...result,
    explanation,
    checks,
  });

  const leaf = await prisma.anchorLeaf.findUnique({
    where: { kind_targetId: { kind, targetId } },
    include: { batch: { include: { contract: true, leaves: { orderBy: { index: "asc" } } } } },
  });
  if (!leaf) {
    return conclude("NOT_ANCHORED", "This item has not been included in an anchored batch yet.");
  }
  const { batch } = leaf;
  const { contract } = batch;
  result.leafIndex = leaf.index;
  result.batch = {
    id: batch.id,
    root: batch.root,
    leafCount: batch.leafCount,
    txHash: batch.txHash,
    blockNumber: batch.blockNumber,
    blockTimestamp: batch.blockTimestamp.toISOString(),
    chainId: contract.chainId,
    contractAddress: contract.address,
  };

  // --- The item is still what was anchored ---
  const commitment = await commitmentFor(kind, targetId);
  if (commitment === null) {
    check("The anchored item still exists", "FAIL");
    return conclude("INVALID", "The anchored item no longer exists.");
  }
  if (!check("The item's commitment, recomputed now, matches the anchored leaf", commitment === leaf.commitment ? "PASS" : "FAIL")) {
    return conclude("INVALID", "The item has changed since it was anchored: its commitment no longer matches the anchored leaf.");
  }

  // --- The stored batch still produces the anchored root ---
  const contiguous = batch.leaves.length === batch.leafCount && batch.leaves.every((candidate, index) => candidate.index === index);
  const leaves = batch.leaves.map((candidate) => Buffer.from(candidate.commitment, "hex"));
  const rebuilt = contiguous ? merkleRoot(leaves).toString("hex") : null;
  if (!check("The stored batch rebuilds the recorded Merkle root", rebuilt === batch.root ? "PASS" : "FAIL")) {
    return conclude("INVALID", "The stored batch no longer rebuilds the root that was anchored: its leaves were altered.");
  }

  const proof = merkleInclusionProof(leaves, leaf.index);
  result.proof = proof.map((node) => node.toString("hex"));
  const included = verifyMerkleInclusion({
    leaf: Buffer.from(commitment, "hex"),
    index: leaf.index,
    treeSize: batch.leafCount,
    proof,
    root: Buffer.from(batch.root, "hex"),
  });
  if (!check(`RFC 6962 inclusion proof for leaf ${leaf.index} of ${batch.leafCount} verifies against the root`, included ? "PASS" : "FAIL")) {
    return conclude("INVALID", "The inclusion proof does not verify.");
  }

  // --- The chain still records that root ---
  try {
    const info = await chainInfo();
    if (info.chainId !== contract.chainId || info.genesisHash !== contract.genesisHash) {
      check(
        "The chain that recorded this anchor is the one answering",
        "UNAVAILABLE",
        `anchored on chain ${contract.chainId} with genesis ${contract.genesisHash.slice(0, 18)}..., but ${info.rpcUrl} is chain ${info.chainId} with genesis ${info.genesisHash.slice(0, 18)}...`,
      );
      return conclude(
        "UNAVAILABLE",
        "The chain instance that recorded this anchor is gone (the local development chain was restarted or replaced), so the anchor cannot be checked. This is not evidence that the item was altered.",
      );
    }
    check("The chain that recorded this anchor is the one answering", "PASS", `chain ${info.chainId} at ${info.rpcUrl}`);

    const onChain = await readAnchor(contract.address as Address, `0x${batch.root}` as Hex);
    if (!check("The recorded address holds the OmniTrust anchor contract", onChain.codeMatches ? "PASS" : "FAIL", contract.address)) {
      return conclude("INVALID", "The recorded contract address does not hold the anchor contract.");
    }
    if (
      !check(
        "The contract records the root in the recorded block",
        onChain.anchoredAtBlock === BigInt(batch.blockNumber) ? "PASS" : "FAIL",
        onChain.anchoredAtBlock === 0n ? "the contract has no record of this root" : `block ${onChain.anchoredAtBlock}`,
      )
    ) {
      return conclude("INVALID", "The chain does not record this root where the batch says it was anchored.");
    }
    const event = onChain.event;
    const eventMatches =
      event !== null && event.leafCount === batch.leafCount && event.blockNumber === BigInt(batch.blockNumber) && event.txHash === batch.txHash;
    if (
      !check(
        "The Anchored event records the same leaf count and transaction",
        eventMatches ? "PASS" : "FAIL",
        event ? `${event.leafCount} leaves in ${event.txHash}` : "no Anchored event for this root",
      )
    ) {
      return conclude("INVALID", "The on-chain record disagrees with the stored batch about its size or transaction.");
    }
    result.anchoredAt = event!.timestamp.toISOString();
  } catch (error) {
    if (!(error instanceof ChainUnavailableError)) throw error;
    check("A chain answers at the configured address", "UNAVAILABLE", error.message);
    return conclude("UNAVAILABLE", `The local chain cannot be reached (${anchorRpcUrl()}), so the anchor cannot be checked. This is not evidence that the item was altered.`);
  }

  return conclude(
    "VALID",
    `The item's commitment is leaf ${leaf.index} of a Merkle tree of ${batch.leafCount} commitments whose root was recorded in block ${batch.blockNumber} of the local development chain at ${result.anchoredAt}. That shows the commitment existed by then on this chain instance. It does not identify anyone, and the chain holds only the root.`,
  );
}

export async function verifyAnchorAs(actor: Actor, kind: AnchorKind, targetId: string) {
  requireCapability(actor, "anchor:read");
  return verifyAnchor(kind, targetId);
}

export async function anchoringOverview(actor: Actor) {
  requireCapability(actor, "anchor:read");

  let chain:
    | { reachable: true; rpcUrl: string; chainId: number; genesisHash: string; blockNumber: string; contract: { address: string; codeMatches: boolean } | null }
    | { reachable: false; rpcUrl: string; reason: string };
  try {
    const info = await chainInfo();
    const contract = await prisma.anchorContract.findUnique({
      where: { chainId_genesisHash: { chainId: info.chainId, genesisHash: info.genesisHash } },
    });
    chain = {
      reachable: true,
      rpcUrl: info.rpcUrl,
      chainId: info.chainId,
      genesisHash: info.genesisHash,
      blockNumber: info.blockNumber.toString(),
      contract: contract ? { address: contract.address, codeMatches: await contractCodeMatches(contract.address as Address) } : null,
    };
  } catch (error) {
    if (!(error instanceof ChainUnavailableError)) throw error;
    chain = { reachable: false, rpcUrl: anchorRpcUrl(), reason: error.message };
  }

  const pending = await pendingCommitments();
  const batches = await prisma.anchorBatch.findMany({
    orderBy: { createdAt: "desc" },
    take: 20,
    include: { contract: true, createdBy: { select: { email: true } } },
  });

  return {
    chain,
    pending: {
      total: pending.length,
      signatures: pending.filter((item) => item.kind === "SIGNATURE").length,
      auditCheckpoints: pending.filter((item) => item.kind === "AUDIT_CHECKPOINT").length,
    },
    batches: batches.map((batch) => ({
      id: batch.id,
      root: batch.root,
      leafCount: batch.leafCount,
      txHash: batch.txHash,
      blockNumber: batch.blockNumber,
      blockTimestamp: batch.blockTimestamp.toISOString(),
      chainId: batch.contract.chainId,
      contractAddress: batch.contract.address,
      onCurrentChain: chain.reachable && batch.contract.genesisHash === chain.genesisHash,
      createdBy: batch.createdBy?.email ?? null,
    })),
  };
}

export type BatchLeaf = { index: number; kind: string; targetId: string; commitment: string; label: string };

export type BatchDetail = {
  batch: {
    id: string;
    root: string;
    leafCount: number;
    txHash: string;
    blockNumber: number;
    blockTimestamp: string;
    chainId: number;
    contractAddress: string;
    createdBy: string | null;
  };
  leaves: BatchLeaf[];
  /** The tree rebuilt from the stored leaves, so the drawing is the computation, not an illustration. */
  tree: MerkleNode | null;
  rebuiltRoot: string | null;
  rootMatches: boolean;
  /** The audit path for the selected leaf, and whether it verifies against the stored root. */
  selected: { index: number; proof: string[]; verifies: boolean } | null;
  onChain:
    | { reachable: true; codeMatches: boolean; anchoredAtBlock: string; event: { leafCount: number; blockNumber: string; timestamp: string; txHash: string } | null }
    | { reachable: false; reason: string };
};

/** What a target is called on screen, so a leaf is not just an opaque commitment. */
async function labelFor(kind: string, targetId: string): Promise<string> {
  if (kind === "SIGNATURE") {
    const signature = await prisma.signature.findUnique({
      where: { id: targetId },
      include: { documentVersion: { include: { document: { select: { filename: true } } } } },
    });
    return signature ? `Signature on ${signature.documentVersion.document.filename} v${signature.documentVersion.versionNumber}` : "Signature (removed)";
  }
  const checkpoint = await prisma.auditCheckpoint.findUnique({ where: { id: targetId } });
  return checkpoint ? `Audit checkpoint at sequence ${checkpoint.seq}` : "Audit checkpoint (removed)";
}

/** One batch, rebuilt from its stored leaves and checked against the chain. */
export async function batchDetail(actor: Actor, batchId: string, selectedIndex?: number): Promise<BatchDetail> {
  requireCapability(actor, "anchor:read");

  const batch = await prisma.anchorBatch.findUnique({
    where: { id: batchId },
    include: { contract: true, createdBy: { select: { email: true } }, leaves: { orderBy: { index: "asc" } } },
  });
  if (!batch) throw new NotFoundError("Anchor batch not found");

  const leaves: BatchLeaf[] = [];
  for (const leaf of batch.leaves) {
    leaves.push({ index: leaf.index, kind: leaf.kind, targetId: leaf.targetId, commitment: leaf.commitment, label: await labelFor(leaf.kind, leaf.targetId) });
  }

  const contiguous = leaves.length === batch.leafCount && leaves.every((leaf, index) => leaf.index === index);
  const buffers = leaves.map((leaf) => Buffer.from(leaf.commitment, "hex"));
  const tree = contiguous ? merkleTree(buffers) : null;
  const rebuiltRoot = contiguous ? merkleRoot(buffers).toString("hex") : null;

  let selected: BatchDetail["selected"] = null;
  if (contiguous && selectedIndex !== undefined && selectedIndex >= 0 && selectedIndex < leaves.length) {
    const proof = merkleInclusionProof(buffers, selectedIndex);
    selected = {
      index: selectedIndex,
      proof: proof.map((node) => node.toString("hex")),
      verifies: verifyMerkleInclusion({
        leaf: buffers[selectedIndex],
        index: selectedIndex,
        treeSize: leaves.length,
        proof,
        root: Buffer.from(batch.root, "hex"),
      }),
    };
  }

  let onChain: BatchDetail["onChain"];
  try {
    const read = await readAnchor(batch.contract.address as Address, `0x${batch.root}` as Hex);
    onChain = {
      reachable: true,
      codeMatches: read.codeMatches,
      anchoredAtBlock: read.anchoredAtBlock.toString(),
      event: read.event
        ? { leafCount: read.event.leafCount, blockNumber: read.event.blockNumber.toString(), timestamp: read.event.timestamp.toISOString(), txHash: read.event.txHash }
        : null,
    };
  } catch (error) {
    onChain = { reachable: false, reason: error instanceof Error ? error.message : "The chain could not be reached" };
  }

  return {
    batch: {
      id: batch.id,
      root: batch.root,
      leafCount: batch.leafCount,
      txHash: batch.txHash,
      blockNumber: batch.blockNumber,
      blockTimestamp: batch.blockTimestamp.toISOString(),
      chainId: batch.contract.chainId,
      contractAddress: batch.contract.address,
      createdBy: batch.createdBy?.email ?? null,
    },
    leaves,
    tree,
    rebuiltRoot,
    rootMatches: rebuiltRoot === batch.root,
    selected,
    onChain,
  };
}
