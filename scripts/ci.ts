// Local continuous integration: every quality gate in one command, with no network access and
// no hosted CI service.
//
//   npm run ci                      run every step, then summarise
//   npm run ci -- --fail-fast       stop at the first failing step
//   npm run ci -- --only lint,typecheck
//   npm run ci -- --skip build
//
// Each tool is started as `node <its JavaScript entry point>` rather than through npm/npx shims,
// because spawning a .cmd shim without a shell fails on Windows. A JSON report is written to
// storage/ci/report.json (gitignored).
import { execFileSync, spawn } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ALGORITHMS } from "../lib/crypto/orchestrator";

const ROOT = process.cwd();
const NODE = process.execPath;
const bin = (...parts: string[]) => path.join(ROOT, "node_modules", ...parts);

export const CI_DIRECTORY = path.join(ROOT, "storage", "ci");
export const SMOKE_OUTPUT = path.join(CI_DIRECTORY, "benchmarks-smoke.json");

/**
 * Every test file belongs to exactly one suite; tests/ci/ci-plan.test.ts fails otherwise, so a
 * new test cannot silently fall outside CI.
 */
export const TEST_SUITES: Record<"unit" | "integration" | "security", string[]> = {
  unit: ["tests/scaffold.test.ts", "tests/crypto", "tests/benchmarks", "tests/ci"],
  integration: ["tests/documents", "tests/pki", "tests/audit", "tests/anchoring", "tests/prisma", "tests/dashboard", "tests/verification"],
  security: ["tests/auth", "tests/http", "tests/api", "tests/security-lab"],
};

export type CiStep = {
  id: string;
  title: string;
  command: string[];
  /** Why the step cannot run here, or null. */
  unavailable: string | null;
  /** Extra in-process check after the command succeeds; returns a failure message or null. */
  verify?: () => string | null;
};

function npmCli(): string | null {
  const candidates = [process.env.npm_execpath, path.join(path.dirname(NODE), "node_modules", "npm", "bin", "npm-cli.js")];
  return candidates.find((candidate) => candidate && candidate.endsWith(".js") && fs.existsSync(candidate)) ?? null;
}

function verifySmokeBenchmark(): string | null {
  if (!fs.existsSync(SMOKE_OUTPUT)) return `no benchmark output at ${path.relative(ROOT, SMOKE_OUTPUT)}`;
  const data = JSON.parse(fs.readFileSync(SMOKE_OUTPUT, "utf8"));
  if (data.schemaVersion !== 2 || data.smoke !== true) return "benchmark output is not a schema-2 smoke run";
  const measured = (data.algorithms as { algorithm: string }[]).map((entry) => entry.algorithm).sort();
  if (JSON.stringify(measured) !== JSON.stringify([...ALGORITHMS].sort())) {
    return `benchmark covered ${measured.join(", ")} but the registry has ${ALGORITHMS.join(", ")}`;
  }
  for (const entry of data.algorithms) {
    for (const payload of entry.payloads) {
      for (const operation of ["hash", "sign", "verify"]) {
        const stats = payload[operation];
        if (stats.n !== data.parameters.iterations || !(stats.medianMs > 0)) {
          return `${entry.algorithm} ${operation}: implausible statistics (n=${stats.n}, median=${stats.medianMs})`;
        }
      }
    }
  }
  return null;
}

export function ciSteps(): CiStep[] {
  const npm = npmCli();
  const tsx = bin("tsx", "dist", "cli.mjs");
  const next = bin("next", "dist", "bin", "next");
  const vitest = bin("vitest", "vitest.mjs");
  const suite = (name: keyof typeof TEST_SUITES): CiStep => ({
    id: `tests-${name}`,
    title: `${name[0].toUpperCase()}${name.slice(1)} tests`,
    command: [NODE, vitest, "run", ...TEST_SUITES[name]],
    unavailable: null,
  });

  return [
    {
      id: "dependencies",
      title: "Installed dependencies match package.json",
      command: npm ? [NODE, npm, "ls", "--depth=0"] : [],
      unavailable: npm ? null : "npm's JavaScript entry point was not found",
    },
    { id: "prisma-schema", title: "Prisma schema is valid", command: [NODE, bin("prisma", "build", "index.js"), "validate"], unavailable: null },
    {
      id: "contract-artifact",
      title: "Anchor contract artifact is a reproducible compile",
      command: [NODE, tsx, "scripts/compile-anchor-contract.ts", "--check"],
      unavailable: null,
    },
    { id: "lint", title: "ESLint", command: [NODE, next, "lint"], unavailable: null },
    { id: "typecheck", title: "TypeScript type-check", command: [NODE, bin("typescript", "bin", "tsc"), "--noEmit", "-p", "."], unavailable: null },
    { id: "crypto-boundary", title: "Crypto boundary check", command: [NODE, tsx, "scripts/check-crypto-boundary.ts"], unavailable: null },
    suite("unit"),
    suite("integration"),
    suite("security"),
    { id: "build", title: "Production build", command: [NODE, next, "build"], unavailable: null },
    {
      id: "benchmark-smoke",
      title: "Benchmark smoke run",
      command: [NODE, tsx, "scripts/benchmark.ts", "--smoke", "--output", SMOKE_OUTPUT],
      unavailable: null,
      verify: verifySmokeBenchmark,
    },
  ];
}

type StepResult = {
  id: string;
  title: string;
  status: "PASS" | "FAIL" | "SKIPPED";
  durationMs: number;
  exitCode: number | null;
  command: string;
  detail: string | null;
  outputTail: string[] | null;
};

function runCommand(command: string[]): Promise<{ exitCode: number | null; tail: string[] }> {
  return new Promise((resolve) => {
    const child = spawn(command[0], command.slice(1), {
      cwd: ROOT,
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, CI: "1", FORCE_COLOR: "0" },
    });
    const tail: string[] = [];
    const keep = (chunk: Buffer, stream: NodeJS.WriteStream) => {
      stream.write(chunk);
      tail.push(...chunk.toString().split(/\r?\n/).filter((line) => line.trim().length > 0));
      if (tail.length > 40) tail.splice(0, tail.length - 40);
    };
    child.stdout.on("data", (chunk: Buffer) => keep(chunk, process.stdout));
    child.stderr.on("data", (chunk: Buffer) => keep(chunk, process.stderr));
    child.on("error", (error) => {
      tail.push(`failed to start: ${error.message}`);
      resolve({ exitCode: null, tail });
    });
    child.on("close", (exitCode) => resolve({ exitCode, tail }));
  });
}

function portInUse(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = net.connect({ port, host: "127.0.0.1" });
    socket.once("connect", () => {
      socket.destroy();
      resolve(true);
    });
    socket.once("error", () => resolve(false));
  });
}

function listArg(flag: string): string[] | null {
  const index = process.argv.indexOf(flag);
  return index === -1 ? null : (process.argv[index + 1] ?? "").split(",").map((value) => value.trim()).filter(Boolean);
}

function git(args: string[]): string | null {
  try {
    return execFileSync("git", args, { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  } catch {
    return null;
  }
}

async function main() {
  const failFast = process.argv.includes("--fail-fast");
  const only = listArg("--only");
  const skip = listArg("--skip") ?? [];
  const steps = ciSteps();
  const known = new Set(steps.map((step) => step.id));
  for (const id of [...(only ?? []), ...skip]) {
    if (!known.has(id)) throw new Error(`Unknown CI step "${id}". Steps: ${[...known].join(", ")}`);
  }

  const startedAt = new Date();
  const results: StepResult[] = [];
  let stopped = false;

  for (const step of steps) {
    const relativeCommand = step.command.map((part, index) => (index === 0 ? "node" : path.isAbsolute(part) ? path.relative(ROOT, part) : part)).join(" ");
    const skipped = (detail: string): StepResult => ({ id: step.id, title: step.title, status: "SKIPPED", durationMs: 0, exitCode: null, command: relativeCommand, detail, outputTail: null });

    if (stopped) {
      results.push(skipped("not run: an earlier step failed and --fail-fast is set"));
      continue;
    }
    if ((only && !only.includes(step.id)) || skip.includes(step.id)) {
      results.push(skipped("not selected"));
      continue;
    }
    if (step.unavailable) {
      results.push({ ...skipped(step.unavailable), status: "FAIL" });
      if (failFast) stopped = true;
      continue;
    }

    console.log(`\n=== ${step.title} (${step.id}) ===\n$ ${relativeCommand}\n`);
    if (step.id === "build" && (await portInUse(3000))) {
      console.log("WARNING: something is listening on port 3000. If it is `next dev`, stop it: the build and the dev server share .next.\n");
    }

    const started = Date.now();
    const { exitCode, tail } = await runCommand(step.command);
    let detail: string | null = exitCode === 0 ? null : `exited with ${exitCode}`;
    if (exitCode === 0 && step.verify) detail = step.verify();
    const status = detail === null ? "PASS" : "FAIL";
    results.push({
      id: step.id,
      title: step.title,
      status,
      durationMs: Date.now() - started,
      exitCode,
      command: relativeCommand,
      detail,
      outputTail: status === "FAIL" ? tail : null,
    });
    if (status === "FAIL" && failFast) stopped = true;
  }

  const finishedAt = new Date();
  const failed = results.filter((result) => result.status === "FAIL");
  const report = {
    startedAt: startedAt.toISOString(),
    finishedAt: finishedAt.toISOString(),
    durationMs: finishedAt.getTime() - startedAt.getTime(),
    node: process.version,
    platform: `${process.platform} ${process.arch}`,
    gitCommit: git(["rev-parse", "--short", "HEAD"]),
    gitTreeDirty: (git(["status", "--porcelain"]) ?? "").length > 0,
    passed: failed.length === 0,
    steps: results,
  };
  fs.mkdirSync(CI_DIRECTORY, { recursive: true });
  fs.writeFileSync(path.join(CI_DIRECTORY, "report.json"), `${JSON.stringify(report, null, 2)}\n`);

  console.log("\n=== CI summary ===");
  for (const result of results) {
    const seconds = result.status === "SKIPPED" ? "" : `${(result.durationMs / 1000).toFixed(1)} s`;
    console.log(`${result.status.padEnd(8)} ${result.id.padEnd(18)} ${seconds.padStart(8)}  ${result.detail ?? ""}`);
  }
  console.log(`\n${report.passed ? "CI PASSED" : `CI FAILED (${failed.length} step${failed.length === 1 ? "" : "s"})`} in ${(report.durationMs / 1000).toFixed(1)} s; report in ${path.relative(ROOT, path.join(CI_DIRECTORY, "report.json"))}`);
  process.exitCode = report.passed ? 0 : 1;
}

const invokedDirectly = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  });
}
