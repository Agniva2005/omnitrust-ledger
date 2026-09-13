// Blockchain anchoring against a real local chain (the Hardhat node tests/global-setup.ts
// starts). Every result comes from real transactions, real contract state and RFC 6962 proofs.
// The failure cases alter real stored data or point at real on-chain state that disagrees.
import fs from "node:fs";
import { beforeAll, describe, expect, it } from "vitest";
import { createPublicClient, createWalletClient, http, type Address, type Hex } from "viem";
import { ANCHOR_ABI, AnchorRejectedError, ChainUnavailableError, deployAnchorContract, submitRoot } from "@/lib/anchoring/chain";
import {
  anchorPending,
  anchoringOverview,
  pendingCommitments,
  verifyAnchor,
} from "@/lib/anchoring/service";
import { ConflictError } from "@/lib/api";
import { AuthorizationError, type Actor } from "@/lib/auth/rbac";
import { merkleRoot, verifyMerkleInclusion } from "@/lib/crypto/merkle";
import { prisma } from "@/lib/db";
import { uploadDocument } from "@/lib/documents/service";
import { signDocument } from "@/lib/documents/signing";
import { ensureRootCa } from "@/lib/pki/ca";
import { issueCertificate } from "@/lib/pki/certificates";
import { createAuditCheckpoint } from "@/lib/pki/audit-checkpoints";
import { CONTRACT_ARTIFACT, compileAnchorContract } from "@/scripts/compile-anchor-contract";
import { seedUsers } from "@/prisma/fixtures";
import { resetDatabase } from "@/tests/helpers/db";
import { ensureMasterKey } from "@/tests/helpers/master-key";

let admin: Actor;
let signer: Actor;
let viewer: Actor;
let certificateId: string;

beforeAll(async () => {
  ensureMasterKey();
  await resetDatabase();
  await seedUsers();
  await ensureRootCa();
  const users = await prisma.user.findMany();
  const actorFor = (email: string, role: Actor["role"]): Actor => ({
    userId: users.find((user) => user.email === email)!.id,
    email,
    role,
  });
  admin = actorFor("admin@demo", "ADMIN");
  signer = actorFor("signer@demo", "SIGNER");
  viewer = actorFor("viewer@demo", "VIEWER");
  certificateId = (await issueCertificate({ actor: signer, algorithm: "ECDSA_P256" })).id;
}, 60_000);

async function signedDocument(text: string) {
  const document = await uploadDocument({
    actor: signer,
    filename: `${Math.random().toString(36).slice(2)}.txt`,
    mimeType: "text/plain",
    bytes: Buffer.from(text),
  });
  await signDocument({ actor: signer, documentId: document.id, certificateId });
  return prisma.signature.findFirstOrThrow({ where: { documentVersion: { documentId: document.id } }, include: { documentVersion: true } });
}

const chainClient = () => createPublicClient({ transport: http(process.env.ANCHOR_RPC_URL) });

async function withChainUrl<T>(url: string, run: () => Promise<T>): Promise<T> {
  const original = process.env.ANCHOR_RPC_URL;
  process.env.ANCHOR_RPC_URL = url;
  try {
    return await run();
  } finally {
    process.env.ANCHOR_RPC_URL = original;
  }
}

describe("the contract artifact", () => {
  it("is a reproducible compile of contracts/OmniTrustAnchor.sol", () => {
    expect(JSON.parse(fs.readFileSync(CONTRACT_ARTIFACT, "utf8"))).toEqual(compileAnchorContract());
  });

  it("has no payable function, so the contract can never hold value", () => {
    expect(ANCHOR_ABI.some((entry) => "stateMutability" in entry && entry.stateMutability === "payable")).toBe(false);
  });
});

describe("anchoring", () => {
  let batch: Awaited<ReturnType<typeof anchorPending>>;
  let signatures: Awaited<ReturnType<typeof signedDocument>>[];

  beforeAll(async () => {
    signatures = [await signedDocument("First anchored document."), await signedDocument("Second anchored document."), await signedDocument("Third anchored document.")];
    await createAuditCheckpoint(admin);
  }, 60_000);

  it("is refused for a non-admin", async () => {
    await expect(anchorPending(signer)).rejects.toThrow(AuthorizationError);
  });

  it("reports an unreachable chain as unavailable rather than failing silently", async () => {
    await withChainUrl("http://127.0.0.1:9", async () => {
      await expect(anchorPending(admin)).rejects.toThrow(ChainUnavailableError);
      const overview = await anchoringOverview(viewer);
      expect(overview.chain.reachable).toBe(false);
    });
  });

  it("anchors every pending signature and audit checkpoint as one Merkle root", async () => {
    const pending = await pendingCommitments();
    expect(pending.filter((item) => item.kind === "SIGNATURE")).toHaveLength(3);
    expect(pending.filter((item) => item.kind === "AUDIT_CHECKPOINT")).toHaveLength(1);

    batch = await anchorPending(admin);
    expect(batch.leafCount).toBe(4);
    expect(batch.root).toBe(merkleRoot(pending.map((item) => Buffer.from(item.commitment, "hex"))).toString("hex"));

    const contract = await prisma.anchorContract.findUniqueOrThrow({ where: { id: batch.contractId } });
    const recorded = await chainClient().readContract({
      address: contract.address as Address,
      abi: ANCHOR_ABI,
      functionName: "anchoredAtBlock",
      args: [`0x${batch.root}`],
    });
    expect(recorded).toBe(BigInt(batch.blockNumber));

    const actions = (await prisma.auditLogEntry.findMany()).map((entry) => entry.action);
    expect(actions).toEqual(expect.arrayContaining(["ANCHOR_CONTRACT_DEPLOYED", "ANCHOR_BATCH_CREATED"]));
    expect(await pendingCommitments()).toHaveLength(0);
  }, 60_000);

  it("sends only the root and the leaf count to the chain", async () => {
    const transaction = await chainClient().getTransaction({ hash: batch.txHash as Hex });
    // 4-byte selector + 32-byte root + 32-byte leaf count, and no value.
    expect(transaction.input.length).toBe(2 + 2 * (4 + 32 + 32));
    expect(transaction.input).toContain(batch.root);
    expect(transaction.value).toBe(0n);
    for (const signature of signatures) {
      expect(transaction.input).not.toContain(signature.documentVersion.hash);
      expect(transaction.input).not.toContain(Buffer.from(signature.signatureBytes).toString("hex").slice(0, 32));
    }
  });

  it("refuses to anchor again when nothing is pending", async () => {
    await expect(anchorPending(admin)).rejects.toThrow(ConflictError);
  });

  it("verifies every anchored item, with a proof that checks independently", async () => {
    const leaves = await prisma.anchorLeaf.findMany({ where: { batchId: batch.id } });
    for (const leaf of leaves) {
      const result = await verifyAnchor(leaf.kind as "SIGNATURE" | "AUDIT_CHECKPOINT", leaf.targetId);
      expect(result.status).toBe("VALID");
      expect(result.checks.every((check) => check.status === "PASS")).toBe(true);
      expect(result.anchoredAt).not.toBeNull();
      expect(
        verifyMerkleInclusion({
          leaf: Buffer.from(leaf.commitment, "hex"),
          index: result.leafIndex!,
          treeSize: result.batch!.leafCount,
          proof: result.proof.map((node) => Buffer.from(node, "hex")),
          root: Buffer.from(result.batch!.root, "hex"),
        }),
      ).toBe(true);
    }
  }, 60_000);

  it("reports a signature made after the batch as not yet anchored, and anchors it in a new batch with a new root", async () => {
    const later = await signedDocument("Signed after the first batch.");
    expect((await verifyAnchor("SIGNATURE", later.id)).status).toBe("NOT_ANCHORED");

    const second = await anchorPending(admin);
    expect(second.leafCount).toBe(1);
    expect(second.root).not.toBe(batch.root);
    expect((await verifyAnchor("SIGNATURE", later.id)).status).toBe("VALID");
  }, 60_000);

  describe("rejections", () => {
    it("INVALID when a signature changed after it was anchored", async () => {
      const target = signatures[0];
      const altered = Buffer.from(target.signatureBytes);
      altered[altered.length - 1] ^= 0x01;
      await prisma.signature.update({ where: { id: target.id }, data: { signatureBytes: new Uint8Array(altered) } });
      try {
        const result = await verifyAnchor("SIGNATURE", target.id);
        expect(result.status).toBe("INVALID");
        expect(result.explanation).toMatch(/changed since it was anchored/);
      } finally {
        await prisma.signature.update({ where: { id: target.id }, data: { signatureBytes: target.signatureBytes } });
      }
    });

    it("INVALID when another leaf of the stored batch was altered", async () => {
      const [first, second] = await prisma.anchorLeaf.findMany({ where: { batchId: batch.id }, orderBy: { index: "asc" } });
      await prisma.anchorLeaf.update({ where: { id: second.id }, data: { commitment: "0".repeat(64) } });
      try {
        const result = await verifyAnchor(first.kind as "SIGNATURE", first.targetId);
        expect(result.status).toBe("INVALID");
        expect(result.explanation).toMatch(/leaves were altered/);
      } finally {
        await prisma.anchorLeaf.update({ where: { id: second.id }, data: { commitment: second.commitment } });
      }
    });

    it("INVALID when the recorded contract is a genuine anchor contract that never saw this root", async () => {
      const contract = await prisma.anchorContract.findUniqueOrThrow({ where: { id: batch.contractId } });
      const fresh = await deployAnchorContract();
      await prisma.anchorContract.update({ where: { id: contract.id }, data: { address: fresh.address } });
      try {
        const result = await verifyAnchor("SIGNATURE", signatures[1].id);
        expect(result.status).toBe("INVALID");
        expect(result.checks.find((check) => check.status === "FAIL")?.detail).toMatch(/no record of this root/);
      } finally {
        await prisma.anchorContract.update({ where: { id: contract.id }, data: { address: contract.address } });
      }
    }, 30_000);

    it("INVALID when the recorded address holds no anchor contract", async () => {
      const contract = await prisma.anchorContract.findUniqueOrThrow({ where: { id: batch.contractId } });
      await prisma.anchorContract.update({ where: { id: contract.id }, data: { address: contract.ownerAddress } });
      try {
        const result = await verifyAnchor("SIGNATURE", signatures[1].id);
        expect(result.status).toBe("INVALID");
        expect(result.explanation).toMatch(/does not hold the anchor contract/);
      } finally {
        await prisma.anchorContract.update({ where: { id: contract.id }, data: { address: contract.address } });
      }
    });

    it("UNAVAILABLE, not INVALID, when the chain that recorded the anchor is gone", async () => {
      const contract = await prisma.anchorContract.findUniqueOrThrow({ where: { id: batch.contractId } });
      await prisma.anchorContract.update({ where: { id: contract.id }, data: { genesisHash: `0x${"12".repeat(32)}` } });
      try {
        const result = await verifyAnchor("SIGNATURE", signatures[1].id);
        expect(result.status).toBe("UNAVAILABLE");
        expect(result.explanation).toMatch(/not evidence that the item was altered/);
      } finally {
        await prisma.anchorContract.update({ where: { id: contract.id }, data: { genesisHash: contract.genesisHash } });
      }
    });

    it("UNAVAILABLE when no chain answers at all", async () => {
      await withChainUrl("http://127.0.0.1:9", async () => {
        expect((await verifyAnchor("SIGNATURE", signatures[1].id)).status).toBe("UNAVAILABLE");
      });
    });
  });

  describe("the contract itself", () => {
    it("refuses a duplicate root, decoding the contract's own error", async () => {
      const contract = await prisma.anchorContract.findUniqueOrThrow({ where: { id: batch.contractId } });
      await expect(submitRoot(contract.address as Address, `0x${batch.root}`, batch.leafCount)).rejects.toThrow(AnchorRejectedError);
      await expect(submitRoot(contract.address as Address, `0x${batch.root}`, batch.leafCount)).rejects.toThrow(/AlreadyAnchored/);
    });

    it("refuses a root from any account but its owner", async () => {
      const contract = await prisma.anchorContract.findUniqueOrThrow({ where: { id: batch.contractId } });
      const wallet = createWalletClient({ transport: http(process.env.ANCHOR_RPC_URL) });
      const [, stranger] = await wallet.getAddresses();
      await expect(
        chainClient().simulateContract({
          address: contract.address as Address,
          abi: ANCHOR_ABI,
          functionName: "anchor",
          args: [`0x${"ef".repeat(32)}`, 1],
          account: stranger,
        }),
      ).rejects.toThrow(/NotOwner/);
    });
  });
});
