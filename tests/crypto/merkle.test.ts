// RFC 6962 Merkle trees. The roots below are the published test vectors of the Certificate
// Transparency reference implementation, computed over the first n of its eight standard
// test leaves. They were not produced by this code: matching all of them, including the
// unbalanced sizes 3, 5, 6 and 7, is the independent evidence that the tree is RFC 6962's.
import { describe, expect, it } from "vitest";
import { sha256 } from "@/lib/crypto/hash";
import {
  merkleInclusionProof,
  merkleLeafHash,
  merkleNodeHash,
  merkleRoot,
  verifyMerkleInclusion,
} from "@/lib/crypto/merkle";

const LEAVES = ["", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f"].map(
  (hex) => Buffer.from(hex, "hex"),
);

const ROOTS = [
  "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
  "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
  "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
  "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
  "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
  "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
  "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
  "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
];

describe("tree hash (RFC 6962 section 2.1)", () => {
  it("hashes the empty tree as SHA-256 of nothing", () => {
    expect(merkleRoot([]).toString("hex")).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
  });

  it.each(ROOTS.map((root, index) => [index + 1, root] as const))(
    "matches the Certificate Transparency test vector for %i leaves",
    (size, root) => {
      expect(merkleRoot(LEAVES.slice(0, size)).toString("hex")).toBe(root);
    },
  );

  it("separates leaves from interior nodes, so a node cannot be passed off as a leaf", () => {
    const [a, b] = [Buffer.from("a"), Buffer.from("b")];
    const node = merkleNodeHash(merkleLeafHash(a), merkleLeafHash(b));
    expect(merkleRoot([a, b]).equals(node)).toBe(true);
    // The two child hashes concatenated, presented as a single leaf, give a different root.
    expect(merkleRoot([Buffer.concat([merkleLeafHash(a), merkleLeafHash(b)])]).equals(node)).toBe(false);
    expect(merkleLeafHash(a).equals(sha256(a))).toBe(false);
  });

  it("does not let an odd leaf count collide with a duplicated last leaf", () => {
    expect(merkleRoot(LEAVES.slice(0, 3)).equals(merkleRoot([...LEAVES.slice(0, 3), LEAVES[2]]))).toBe(false);
  });
});

describe("inclusion proofs (RFC 6962 PATH, verified per RFC 9162 section 2.1.3.2)", () => {
  it("proves and verifies every leaf of every tree size from 1 to 8", () => {
    for (let size = 1; size <= LEAVES.length; size += 1) {
      const leaves = LEAVES.slice(0, size);
      const root = merkleRoot(leaves);
      for (let index = 0; index < size; index += 1) {
        const proof = merkleInclusionProof(leaves, index);
        expect(verifyMerkleInclusion({ leaf: leaves[index], index, treeSize: size, proof, root })).toBe(true);
      }
    }
  });

  it("produces the published audit path length: ceil(log2(n)) for leaf 0", () => {
    expect(merkleInclusionProof(LEAVES, 0)).toHaveLength(3);
    expect(merkleInclusionProof(LEAVES.slice(0, 5), 4)).toHaveLength(1);
    expect(merkleInclusionProof(LEAVES.slice(0, 1), 0)).toHaveLength(0);
  });

  it("also verifies trees of many sizes built from random 32-byte commitments", () => {
    for (const size of [2, 9, 16, 17, 31, 100]) {
      const leaves = Array.from({ length: size }, (_, index) => sha256(`commitment ${size} ${index}`));
      const root = merkleRoot(leaves);
      for (const index of [0, Math.floor(size / 2), size - 1]) {
        const proof = merkleInclusionProof(leaves, index);
        expect(verifyMerkleInclusion({ leaf: leaves[index], index, treeSize: size, proof, root })).toBe(true);
      }
    }
  });

  describe("rejects", () => {
    const leaves = LEAVES.slice(0, 7);
    const root = merkleRoot(leaves);
    const index = 3;
    const proof = merkleInclusionProof(leaves, index);
    const claim = { leaf: leaves[index], index, treeSize: 7, proof, root };

    it("a different leaf", () => {
      expect(verifyMerkleInclusion({ ...claim, leaf: Buffer.from("not in the tree") })).toBe(false);
    });

    it("the right leaf at the wrong index", () => {
      expect(verifyMerkleInclusion({ ...claim, index: 2 })).toBe(false);
    });

    it("a tree size that changes the path's shape, or excludes the index", () => {
      expect(verifyMerkleInclusion({ ...claim, treeSize: 4 })).toBe(false);
      expect(verifyMerkleInclusion({ ...claim, treeSize: 3 })).toBe(false);
    });

    it("but not every wrong tree size: the proof alone does not bind the size, so the anchor must", () => {
      // Leaf 3 sits in the left subtree of size 4 in both a 7-leaf and an 8-leaf tree, so the
      // RFC 9162 walk takes the same directions and the same proof verifies for either claimed
      // size. RFC 9162 authenticates tree size through the signed tree head; here the leaf
      // count is recorded on-chain with the root, and anchor verification compares it.
      expect(verifyMerkleInclusion({ ...claim, treeSize: 8 })).toBe(true);
    });

    it("a tampered proof node, a truncated proof, or an extended proof", () => {
      const tampered = proof.map((node, position) => (position === 1 ? Buffer.from(node).fill(0) : node));
      expect(verifyMerkleInclusion({ ...claim, proof: tampered })).toBe(false);
      expect(verifyMerkleInclusion({ ...claim, proof: proof.slice(0, -1) })).toBe(false);
      expect(verifyMerkleInclusion({ ...claim, proof: [...proof, proof[0]] })).toBe(false);
    });

    it("a different root", () => {
      expect(verifyMerkleInclusion({ ...claim, root: merkleRoot(LEAVES) })).toBe(false);
    });

    it("an index outside the tree, and malformed node lengths, without throwing", () => {
      expect(verifyMerkleInclusion({ ...claim, index: 7 })).toBe(false);
      expect(verifyMerkleInclusion({ ...claim, index: -1 })).toBe(false);
      expect(verifyMerkleInclusion({ ...claim, proof: [Buffer.alloc(31), ...proof.slice(1)] })).toBe(false);
      expect(() => merkleInclusionProof(leaves, 7)).toThrow(RangeError);
    });
  });
});
