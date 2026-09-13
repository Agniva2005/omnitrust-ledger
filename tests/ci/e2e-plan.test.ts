// The end-to-end regression must never touch the development installation. Starting servers
// here would be slow and recursive, so this checks the isolation plan itself; `npm run e2e` is
// the real run.
import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { E2E_CHAIN_PORT, E2E_PORT, E2E_ROOT, e2eEnvironment } from "@/scripts/e2e";

const ROOT = process.cwd();
const within = (child: string, parent: string) => {
  const relative = path.relative(parent, child);
  return relative !== "" && !relative.startsWith("..") && !path.isAbsolute(relative);
};

describe("the E2E isolation plan", () => {
  const runDirectory = path.join(E2E_ROOT, "1234-abcdef");
  const env = e2eEnvironment(runDirectory);

  it("keeps the database, storage, master key and Security Lab root inside the run directory", () => {
    const database = env.DATABASE_URL.replace(/^file:/, "");
    for (const location of [database, env.STORAGE_ROOT, env.MASTER_KEY_PATH, env.SECURITY_LAB_ROOT]) {
      expect(within(path.resolve(location), runDirectory), location).toBe(true);
    }
    expect(within(runDirectory, path.join(ROOT, "storage"))).toBe(true);
    expect(fs.readFileSync(path.join(ROOT, ".gitignore"), "utf8")).toMatch(/^storage\/$/m);
  });

  it("never refers to the development database, storage or key", () => {
    const serialised = JSON.stringify(env);
    expect(serialised).not.toContain("dev.db");
    expect(path.resolve(env.STORAGE_ROOT)).not.toBe(path.join(ROOT, "storage"));
    expect(path.resolve(env.MASTER_KEY_PATH)).not.toBe(path.join(ROOT, "storage", "keys", "master.key"));
  });

  it("uses ports apart from the dev server, npm run chain and the test chain, and a fresh secret each run", () => {
    expect([3000, 8545, 8546]).not.toContain(E2E_PORT);
    expect([3000, 8545, 8546]).not.toContain(E2E_CHAIN_PORT);
    expect(env.ANCHOR_RPC_URL).toBe(`http://127.0.0.1:${E2E_CHAIN_PORT}`);
    expect(env.JWT_SECRET).toMatch(/^[0-9a-f]{64}$/);
    expect(e2eEnvironment(runDirectory).JWT_SECRET).not.toBe(env.JWT_SECRET);
    expect(env.NODE_ENV).toBe("production");
  });

  it("is what `npm run e2e` runs", () => {
    const scripts = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8")).scripts;
    expect(scripts.e2e).toBe("tsx scripts/e2e.ts");
  });
});
