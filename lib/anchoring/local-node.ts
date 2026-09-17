// Starting and stopping the local development chain from the application.
//
// The chain is a Hardhat node in its own process. It was previously only startable from a
// terminal, which meant the Anchoring page could be dead during a demonstration with no way to
// revive it from the interface. This runs the same command `npm run chain` does.
//
// It is a development convenience and nothing more: the node is a throwaway chain on localhost
// with well-known development accounts, and the route is ADMIN-only. A real deployment would
// point at a real chain and would not start one.
import { spawn } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";
import { ConflictError } from "@/lib/api";
import { requireCapability, type Actor } from "@/lib/auth/rbac";
import { anchorRpcUrl } from "@/lib/anchoring/chain";
import { storageRoot } from "@/lib/documents/storage";

const START_TIMEOUT_MS = 30_000;
const POLL_INTERVAL_MS = 400;

function pidFile(): string {
  return path.join(storageRoot(), "chain.pid");
}

function hardhatCli(): string {
  return path.join(process.cwd(), "node_modules", "hardhat", "internal", "cli", "bootstrap.js");
}

/** The RPC endpoint's host and port, so the node is started where the application looks for it. */
function endpoint(): { host: string; port: string } {
  const url = new URL(anchorRpcUrl());
  return { host: url.hostname, port: url.port || "8545" };
}

/** A JSON-RPC probe: the only thing that actually proves a chain is answering. */
export async function chainReachable(): Promise<boolean> {
  try {
    const response = await fetch(anchorRpcUrl(), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", method: "eth_blockNumber", params: [], id: 1 }),
      signal: AbortSignal.timeout(2000),
    });
    return response.ok;
  } catch {
    return false;
  }
}

/** Whether a process id still exists. Signal 0 checks without delivering anything. */
function alive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

/**
 * The node this application started, if it is still running. A recorded id whose process has
 * gone is cleared: leaving it would offer a Stop button for a chain that is not there.
 */
async function recordedPid(): Promise<number | null> {
  let pid: number;
  try {
    pid = Number.parseInt(await fs.readFile(pidFile(), "utf8"), 10);
  } catch {
    return null;
  }
  if (!Number.isInteger(pid)) return null;
  if (alive(pid)) return pid;
  await fs.rm(pidFile(), { force: true });
  return null;
}

export type NodeStatus = {
  reachable: boolean;
  rpcUrl: string;
  /** Set only when this application started the node, so the interface knows it can stop it. */
  startedByApp: number | null;
};

export async function nodeStatus(): Promise<NodeStatus> {
  const pid = await recordedPid();
  return { reachable: await chainReachable(), rpcUrl: anchorRpcUrl(), startedByApp: pid };
}

/** Starts the node detached, and waits until it actually answers before reporting success. */
export async function startLocalChain(actor: Actor): Promise<NodeStatus> {
  requireCapability(actor, "anchor:create");
  if (await chainReachable()) throw new ConflictError("A chain is already answering at that address");

  const { host, port } = endpoint();
  const child = spawn(process.execPath, [hardhatCli(), "node", "--hostname", host, "--port", port], {
    cwd: process.cwd(),
    // Detached with no pipes: the node must outlive the request that started it.
    detached: true,
    stdio: "ignore",
    env: { ...process.env },
  });
  child.unref();

  if (child.pid) {
    await fs.mkdir(path.dirname(pidFile()), { recursive: true });
    await fs.writeFile(pidFile(), String(child.pid));
  }

  const deadline = Date.now() + START_TIMEOUT_MS;
  while (Date.now() < deadline) {
    if (await chainReachable()) return nodeStatus();
    await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
  }

  throw new ConflictError(`The chain did not answer at ${anchorRpcUrl()} within ${START_TIMEOUT_MS / 1000} seconds`);
}

/** Stops only a node this application started; a chain someone else is running is left alone. */
export async function stopLocalChain(actor: Actor): Promise<NodeStatus> {
  requireCapability(actor, "anchor:create");

  const pid = await recordedPid();
  if (pid === null) throw new ConflictError("This application did not start the chain, so it will not stop it");

  try {
    process.kill(pid);
  } catch {
    // Already gone; clearing the record below is the right outcome either way.
  }
  await fs.rm(pidFile(), { force: true });

  const deadline = Date.now() + 5000;
  while (Date.now() < deadline && (await chainReachable())) {
    await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
  }
  return nodeStatus();
}
