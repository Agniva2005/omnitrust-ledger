// The Security Lab. Every scenario runs its real attack against the throwaway test database
// and must report that the control held; the isolation guard must refuse anything that is not
// a sandbox; and one full sandboxed run must leave the calling process's database untouched.
import fs from "node:fs";
import path from "node:path";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { AuthorizationError, type Actor } from "@/lib/auth/rbac";
import { loginRateLimit } from "@/lib/auth/rate-limit";
import { prisma } from "@/lib/db";
import { SCENARIOS, isScenarioId } from "@/lib/security-lab/catalog";
import { SandboxViolationError, assertSandbox, labRoot } from "@/lib/security-lab/guard";
import { runScenarioInSandbox } from "@/lib/security-lab/sandbox";
import { hasImplementation, runScenario } from "@/lib/security-lab/scenarios";
import { listScenarios, runSecurityLab } from "@/lib/security-lab/service";
import { resetDatabase } from "@/tests/helpers/db";
import { ensureMasterKey } from "@/tests/helpers/master-key";

const LAB_ROOT = path.join(process.cwd(), "storage", "test", "lab");
const originalLabRoot = process.env.SECURITY_LAB_ROOT;

beforeAll(() => {
  ensureMasterKey();
  process.env.SECURITY_LAB_ROOT = LAB_ROOT;
});

afterAll(() => {
  process.env.SECURITY_LAB_ROOT = originalLabRoot;
  loginRateLimit.clear();
});

describe("the catalogue", () => {
  it("implements every scenario it lists, with unique ids, including an honest control", () => {
    const ids = SCENARIOS.map((scenario) => scenario.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const id of ids) expect(hasImplementation(id)).toBe(true);
    expect(SCENARIOS.some((scenario) => scenario.category === "control")).toBe(true);
    expect(isScenarioId("drop-production-database")).toBe(false);
  });
});

describe("every attack, run for real against the test database", () => {
  beforeEach(async () => {
    await resetDatabase();
    loginRateLimit.clear();
  });

  it.each(SCENARIOS.map((scenario) => [scenario.id] as const))("%s: the control holds", async (id) => {
    const result = await runScenario(id);
    expect(result.outcome, `${result.observed} ${JSON.stringify(result.evidence)}`).toBe("HELD");
    expect(result.observed.length).toBeGreaterThan(0);
  }, 60_000);
});

describe("the isolation guard", () => {
  const lab = path.join(process.cwd(), "storage", "lab");
  const run = path.join(lab, "runs", "123-abc");
  const sandbox = {
    OMNITRUST_SECURITY_LAB: "1",
    SECURITY_LAB_ROOT: lab,
    DATABASE_URL: `file:${path.join(run, "lab.db")}`,
    STORAGE_ROOT: path.join(run, "storage"),
    MASTER_KEY_PATH: path.join(run, "keys", "master.key"),
  };

  it("accepts a complete sandbox run directory", () => {
    expect(() => assertSandbox(sandbox)).not.toThrow();
  });

  it("refuses the development database, whatever else is set", () => {
    expect(() => assertSandbox({ ...sandbox, DATABASE_URL: "file:./dev.db" })).toThrow(SandboxViolationError);
    expect(() => assertSandbox({ ...sandbox, DATABASE_URL: "file:./dev.db", VITEST: "true" })).toThrow(SandboxViolationError);
  });

  it("refuses a sandbox database paired with the real storage or master key", () => {
    expect(() => assertSandbox({ ...sandbox, STORAGE_ROOT: path.join(process.cwd(), "storage") })).toThrow(SandboxViolationError);
    expect(() => assertSandbox({ ...sandbox, MASTER_KEY_PATH: path.join(process.cwd(), "storage", "keys", "master.key") })).toThrow(SandboxViolationError);
  });

  it("refuses a lab-shaped path unless the sandbox flag is set, and refuses parts spread over two runs", () => {
    expect(() => assertSandbox({ ...sandbox, OMNITRUST_SECURITY_LAB: undefined })).toThrow(SandboxViolationError);
    expect(() => assertSandbox({ ...sandbox, STORAGE_ROOT: path.join(lab, "runs", "999-other", "storage") })).toThrow(SandboxViolationError);
  });

  it("refuses to run a scenario when the process is not pointed at a sandbox", async () => {
    const original = process.env.DATABASE_URL;
    process.env.DATABASE_URL = "file:./dev.db";
    try {
      await expect(runScenario("control-untouched")).rejects.toThrow(SandboxViolationError);
    } finally {
      process.env.DATABASE_URL = original;
    }
  });
});

describe("a full sandboxed run", () => {
  let admin: Actor;
  let verifier: Actor;

  beforeAll(async () => {
    await resetDatabase();
    const { seedUsers } = await import("@/prisma/fixtures");
    await seedUsers();
    const users = await prisma.user.findMany();
    admin = { userId: users.find((user) => user.email === "admin@demo")!.id, email: "admin@demo", role: "ADMIN" };
    verifier = { userId: users.find((user) => user.email === "verifier@demo")!.id, email: "verifier@demo", role: "VERIFIER" };
  });

  it("is admin-only", async () => {
    expect(() => listScenarios(verifier)).toThrow(AuthorizationError);
    await expect(runSecurityLab(verifier, "control-untouched")).rejects.toThrow(AuthorizationError);
    await expect(runSecurityLab(admin, "not-a-scenario")).rejects.toThrow(/Unknown Security Lab scenario/);
  });

  it("runs in its own process and database, deletes the sandbox, and leaves this database untouched", async () => {
    expect(labRoot()).toBe(LAB_ROOT);
    const documentsBefore = await prisma.document.count();

    const run = await runSecurityLab(admin, "document-substitution");

    expect(run.result.outcome).toBe("HELD");
    expect(run.result.evidence).toMatchObject({ outcome: "INVALID", reason: "HASH_MISMATCH" });
    expect(run.sandboxRemoved).toBe(true);
    expect(fs.existsSync(path.join(LAB_ROOT, "runs", run.runId))).toBe(false);
    expect(run.production.untouched).toBe(true);
    // The attack signed and tampered a document, but in the sandbox, not here.
    expect(await prisma.document.count()).toBe(documentsBefore);

    const entry = await prisma.auditLogEntry.findFirstOrThrow({ where: { action: "SECURITY_LAB_RUN" } });
    expect(JSON.parse(entry.metadataJson)).toMatchObject({ outcome: "HELD", productionUntouched: true, sandboxRemoved: true });
  }, 240_000);

  it("reuses the migrated template rather than migrating on every run", async () => {
    const started = Date.now();
    const run = await runScenarioInSandbox("control-untouched");
    expect(run.result.outcome).toBe("HELD");
    expect(Date.now() - started).toBeLessThan(120_000);
    expect(fs.existsSync(path.join(LAB_ROOT, "template.db"))).toBe(true);
  }, 240_000);
});
