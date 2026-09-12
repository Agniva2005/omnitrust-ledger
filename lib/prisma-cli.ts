import { execFileSync } from "node:child_process";
import path from "node:path";

const CLI = path.join(process.cwd(), "node_modules", "prisma", "build", "index.js");

/**
 * Runs the Prisma CLI through node directly rather than `npx`. On Windows,
 * spawning the `npx.cmd` shim without a shell fails with EINVAL, and enabling
 * the shell would mean argument concatenation instead of escaping.
 */
export function prismaCli(args: string[], env: Record<string, string | undefined> = {}) {
  execFileSync(process.execPath, [CLI, ...args], {
    stdio: "inherit",
    env: { ...process.env, ...env },
  });
}

export function prismaCliQuiet(args: string[], env: Record<string, string | undefined> = {}) {
  execFileSync(process.execPath, [CLI, ...args], {
    stdio: "pipe",
    env: { ...process.env, ...env },
  });
}
