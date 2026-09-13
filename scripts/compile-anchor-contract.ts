// Compiles contracts/OmniTrustAnchor.sol with the pinned solc package and writes the ABI and
// bytecode the app deploys, so the deployed code is reproducible from the committed source.
//
//   npm run contract:compile           writes lib/anchoring/anchor-contract.json
//   npm run contract:compile -- --check  fails if the committed artifact differs from a fresh compile
import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { sha256Hex } from "../lib/crypto/hash";

const require = createRequire(import.meta.url);

export const CONTRACT_SOURCE = path.join(process.cwd(), "contracts", "OmniTrustAnchor.sol");
export const CONTRACT_ARTIFACT = path.join(process.cwd(), "lib", "anchoring", "anchor-contract.json");

const SETTINGS = {
  optimizer: { enabled: true, runs: 200 },
  // The local Hardhat node runs the Cancun hardfork (hardhat.config.cjs).
  evmVersion: "cancun",
  outputSelection: {
    "*": {
      OmniTrustAnchor: ["abi", "evm.bytecode.object", "evm.deployedBytecode.object", "evm.deployedBytecode.immutableReferences"],
    },
  },
} as const;

type SolcOutput = {
  errors?: { severity: string; formattedMessage: string }[];
  contracts?: Record<
    string,
    Record<
      string,
      {
        abi: unknown[];
        evm: {
          bytecode: { object: string };
          deployedBytecode: { object: string; immutableReferences?: Record<string, { start: number; length: number }[]> };
        };
      }
    >
  >;
};

export function compileAnchorContract() {
  const solc = require("solc") as { compile(input: string): string; version(): string };
  const source = fs.readFileSync(CONTRACT_SOURCE, "utf8").replace(/\r\n/g, "\n");
  const output = JSON.parse(
    solc.compile(
      JSON.stringify({
        language: "Solidity",
        sources: { "OmniTrustAnchor.sol": { content: source } },
        settings: SETTINGS,
      }),
    ),
  ) as SolcOutput;

  const errors = (output.errors ?? []).filter((entry) => entry.severity === "error");
  if (errors.length > 0) throw new Error(errors.map((entry) => entry.formattedMessage).join("\n"));
  const contract = output.contracts?.["OmniTrustAnchor.sol"]?.OmniTrustAnchor;
  if (!contract) throw new Error("solc produced no OmniTrustAnchor contract");

  return {
    contractName: "OmniTrustAnchor",
    compiler: { name: "solc", version: solc.version(), settings: { optimizer: SETTINGS.optimizer, evmVersion: SETTINGS.evmVersion } },
    sourceSha256: sha256Hex(source),
    abi: contract.abi,
    bytecode: contract.evm.bytecode.object,
    deployedBytecode: contract.evm.deployedBytecode.object,
    immutableReferences: contract.evm.deployedBytecode.immutableReferences ?? {},
  };
}

function main() {
  const artifact = `${JSON.stringify(compileAnchorContract(), null, 2)}\n`;
  if (process.argv.includes("--check")) {
    const committed = fs.existsSync(CONTRACT_ARTIFACT) ? fs.readFileSync(CONTRACT_ARTIFACT, "utf8").replace(/\r\n/g, "\n") : "";
    if (committed !== artifact) {
      console.error(`${path.relative(process.cwd(), CONTRACT_ARTIFACT)} does not match a fresh compile. Run npm run contract:compile.`);
      process.exitCode = 1;
      return;
    }
    console.log("Anchor contract artifact matches a fresh compile.");
    return;
  }
  fs.mkdirSync(path.dirname(CONTRACT_ARTIFACT), { recursive: true });
  fs.writeFileSync(CONTRACT_ARTIFACT, artifact);
  console.log(`Wrote ${path.relative(process.cwd(), CONTRACT_ARTIFACT)}`);
}

const invokedDirectly = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) main();
