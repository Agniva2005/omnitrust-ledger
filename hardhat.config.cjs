// Hardhat 2 configuration for the local development chain used by blockchain anchoring.
//
// Used only to run `npm run chain` (a local JSON-RPC node on 127.0.0.1). Nothing is compiled
// with Hardhat: the anchor contract is compiled reproducibly by scripts/compile-anchor-contract.ts
// with the pinned solc package, and deployed by the app. The node is in-memory: its state,
// including every anchor, is lost when it stops. Its accounts are Hardhat's public development
// accounts and must never hold real value.
module.exports = {
  networks: {
    hardhat: {
      chainId: 31337,
      hardfork: "cancun",
    },
  },
};
