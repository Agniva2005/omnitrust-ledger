// Builds a throwaway SQLite database (prisma/test.db) before the suite runs, so
// tests never touch the dev database, and starts a throwaway local chain for the
// anchoring tests.
//
// Deletes the previous test.db and applies the committed migrations forward with
// `migrate deploy`. Deliberately avoids `db push --force-reset`: no destructive
// Prisma command is ever run here, and applying the real migrations means the
// suite also proves the committed migration history builds a working schema.
//
// The chain is an in-memory Hardhat node on 127.0.0.1:8546 (tests/setup.ts points
// ANCHOR_RPC_URL at it), stopped when the suite ends. Its stdout is discarded:
// Hardhat prints its public development account keys there, and no key of any kind
// should end up in test output.
import { spawn, type ChildProcess } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { prismaCliQuiet } from "../lib/prisma-cli";

const TEST_CHAIN_URL = "http://127.0.0.1:8546";
const CHAIN_START_TIMEOUT_MS = 120_000;

async function chainAnswers(): Promise<boolean> {
  try {
    const response = await fetch(TEST_CHAIN_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_chainId", params: [] }),
    });
    return response.ok;
  } catch {
    return false;
  }
}

async function startTestChain(root: string): Promise<ChildProcess | null> {
  if (await chainAnswers()) return null;

  const child = spawn(
    process.execPath,
    [path.join(root, "node_modules", "hardhat", "internal", "cli", "bootstrap.js"), "node", "--hostname", "127.0.0.1", "--port", "8546"],
    { cwd: root, stdio: ["ignore", "ignore", "pipe"] },
  );
  let stderr = "";
  child.stderr?.on("data", (chunk) => {
    stderr += chunk;
  });

  const started = Date.now();
  while (!(await chainAnswers())) {
    if (child.exitCode !== null) {
      throw new Error(`The test chain (hardhat node) exited with ${child.exitCode}: ${stderr.slice(0, 500)}`);
    }
    if (Date.now() - started > CHAIN_START_TIMEOUT_MS) {
      child.kill();
      throw new Error("The test chain (hardhat node) did not start within 120 s");
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  return child;
}

export default async function setup() {
  const root = process.cwd();

  fs.rmSync(path.join(root, "storage", "test"), { recursive: true, force: true });
  for (const suffix of ["", "-journal"]) {
    fs.rmSync(path.join(root, "prisma", `test.db${suffix}`), { force: true });
  }

  prismaCliQuiet(["migrate", "deploy"], { DATABASE_URL: "file:./test.db" });

  const chain = await startTestChain(root);
  return () => {
    chain?.kill();
  };
}
