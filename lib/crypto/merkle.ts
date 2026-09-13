// Cryptographic layer: Merkle trees as specified by RFC 6962 section 2.1 (Certificate
// Transparency), with the inclusion-proof verification algorithm of RFC 9162 section 2.1.3.2.
//
//   MTH({})       = SHA-256()
//   MTH({d0})     = SHA-256(0x00 || d0)
//   MTH(D[n])     = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n])),  k = largest power of 2 < n
//
// The distinct 0x00 / 0x01 prefixes for leaves and interior nodes prevent a second-preimage
// attack in which an interior node is presented as a leaf. Unbalanced trees follow the RFC
// split rather than duplicating the last leaf, so no two different leaf lists share a root.
import { sha256 } from "@/lib/crypto/hash";

const LEAF_PREFIX = Buffer.from([0x00]);
const NODE_PREFIX = Buffer.from([0x01]);

export function merkleLeafHash(data: Uint8Array): Buffer {
  return sha256(Buffer.concat([LEAF_PREFIX, data]));
}

export function merkleNodeHash(left: Uint8Array, right: Uint8Array): Buffer {
  return sha256(Buffer.concat([NODE_PREFIX, left, right]));
}

/** The largest power of two strictly less than n (n > 1). */
function splitPoint(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

function rootOfHashes(hashes: Buffer[]): Buffer {
  if (hashes.length === 0) return sha256(new Uint8Array(0));
  if (hashes.length === 1) return hashes[0];
  const k = splitPoint(hashes.length);
  return merkleNodeHash(rootOfHashes(hashes.slice(0, k)), rootOfHashes(hashes.slice(k)));
}

/** MTH over the leaf data (each element is hashed as a leaf). */
export function merkleRoot(leaves: readonly Uint8Array[]): Buffer {
  return rootOfHashes(leaves.map(merkleLeafHash));
}

function pathOfHashes(index: number, hashes: Buffer[]): Buffer[] {
  if (hashes.length <= 1) return [];
  const k = splitPoint(hashes.length);
  return index < k
    ? [...pathOfHashes(index, hashes.slice(0, k)), rootOfHashes(hashes.slice(k))]
    : [...pathOfHashes(index - k, hashes.slice(k)), rootOfHashes(hashes.slice(0, k))];
}

/** PATH(m, D[n]): the audit path proving leaf `index` is in the tree, leaf-side first. */
export function merkleInclusionProof(leaves: readonly Uint8Array[], index: number): Buffer[] {
  if (!Number.isInteger(index) || index < 0 || index >= leaves.length) {
    throw new RangeError(`Leaf index ${index} is outside a tree of ${leaves.length} leaves`);
  }
  return pathOfHashes(index, leaves.map(merkleLeafHash));
}

export type InclusionClaim = {
  /** The leaf data, not its hash. */
  leaf: Uint8Array;
  index: number;
  treeSize: number;
  proof: readonly Uint8Array[];
  root: Uint8Array;
};

/** RFC 9162 section 2.1.3.2. Returns false for any malformed or non-matching proof; never throws. */
export function verifyMerkleInclusion(claim: InclusionClaim): boolean {
  const { index, treeSize, proof, root } = claim;
  if (!Number.isInteger(index) || !Number.isInteger(treeSize) || index < 0 || index >= treeSize) return false;
  if (proof.some((node) => node.length !== 32) || root.length !== 32) return false;

  let fn = index;
  let sn = treeSize - 1;
  let r = merkleLeafHash(claim.leaf);

  for (const p of proof) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      r = merkleNodeHash(p, r);
      if (fn % 2 === 0) {
        while (fn % 2 === 0 && fn !== 0) {
          fn = Math.floor(fn / 2);
          sn = Math.floor(sn / 2);
        }
      }
    } else {
      r = merkleNodeHash(r, p);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }

  return sn === 0 && Buffer.from(r).equals(Buffer.from(root));
}
