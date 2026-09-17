// The evaluation matrix, assembled from the audit log.
//
// The property that matters is honesty: a scenario nobody has run must never be counted as a
// pass, and a capability must not read as demonstrated until every scenario written for it has
// actually held here. A table that flattered the system would be worse than no table.
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { appendAuditEntry } from "@/lib/audit/log";
import { AuthorizationError, type Actor } from "@/lib/auth/rbac";
import { prisma } from "@/lib/db";
import { SCENARIOS } from "@/lib/security-lab/catalog";
import { buildEvaluation } from "@/lib/security-lab/evaluation";
import { seedUsers } from "@/prisma/fixtures";
import { resetDatabase } from "@/tests/helpers/db";
import { ensureMasterKey } from "@/tests/helpers/master-key";

let admin: Actor;
let signer: Actor;

async function recordRun(scenarioId: string, outcome: string, extra: Record<string, unknown> = {}) {
  await appendAuditEntry({
    actorUserId: admin.userId,
    action: "SECURITY_LAB_RUN",
    targetType: "SecurityLabScenario",
    targetId: scenarioId,
    metadata: { outcome, durationMs: 1234, sandboxRemoved: true, productionUntouched: true, ...extra },
  });
}

beforeAll(() => {
  ensureMasterKey();
});

beforeEach(async () => {
  await resetDatabase();
  await seedUsers();
  const users = await prisma.user.findMany();
  const id = (email: string) => users.find((user) => user.email === email)!.id;
  admin = { userId: id("admin@demo"), email: "admin@demo", role: "ADMIN" };
  signer = { userId: id("signer@demo"), email: "signer@demo", role: "SIGNER" };
});

describe("the adversarial evaluation", () => {
  it("counts a scenario nobody has run as never run, not as a pass", async () => {
    const evaluation = await buildEvaluation(admin);

    expect(evaluation.totals.scenarios).toBe(SCENARIOS.length);
    expect(evaluation.totals.neverRun).toBe(SCENARIOS.length);
    expect(evaluation.totals.held).toBe(0);
    expect(evaluation.rows.every((row) => row.latest === null)).toBe(true);
    // With nothing run, no capability may read as demonstrated.
    expect(evaluation.coverage.every((row) => row.fullyDemonstrated === false)).toBe(true);
  });

  it("reports the most recent run of a scenario, not the best one", async () => {
    const id = SCENARIOS[0].id;
    await recordRun(id, "HELD");
    await recordRun(id, "FAILED");

    const evaluation = await buildEvaluation(admin);
    const row = evaluation.rows.find((candidate) => candidate.scenario.id === id)!;
    expect(row.latest?.outcome).toBe("FAILED");
    expect(row.runCount).toBe(2);
    expect(evaluation.totals.failed).toBe(1);
    expect(evaluation.totals.held).toBe(0);
  });

  it("carries the audit entry each result came from, so it can be checked", async () => {
    const id = SCENARIOS[0].id;
    await recordRun(id, "HELD");

    const evaluation = await buildEvaluation(admin);
    const row = evaluation.rows.find((candidate) => candidate.scenario.id === id)!;
    const entry = await prisma.auditLogEntry.findFirstOrThrow({ where: { action: "SECURITY_LAB_RUN" }, orderBy: { seq: "desc" } });

    expect(row.latest?.auditSeq).toBe(entry.seq);
    expect(row.latest?.auditHash).toBe(entry.entryHash);
  });

  it("marks a capability demonstrated only when every scenario for it has held", async () => {
    // A capability with more than one scenario, so partial coverage is distinguishable.
    const capability = SCENARIOS.map((scenario) => scenario.adversary).find(
      (adversary, _index, all) => all.filter((candidate) => candidate === adversary).length > 1,
    )!;
    const mine = SCENARIOS.filter((scenario) => scenario.adversary === capability);
    expect(mine.length).toBeGreaterThan(1);

    await recordRun(mine[0].id, "HELD");
    let coverage = (await buildEvaluation(admin)).coverage.find((row) => row.adversary === capability)!;
    expect(coverage.held).toBe(1);
    expect(coverage.fullyDemonstrated, "one of several scenarios is not the whole capability").toBe(false);

    for (const scenario of mine.slice(1)) await recordRun(scenario.id, "HELD");
    coverage = (await buildEvaluation(admin)).coverage.find((row) => row.adversary === capability)!;
    expect(coverage.fullyDemonstrated).toBe(true);
  });

  it("never marks a capability demonstrated when one of its scenarios failed", async () => {
    const capability = SCENARIOS.map((scenario) => scenario.adversary).find(
      (adversary, _index, all) => all.filter((candidate) => candidate === adversary).length > 1,
    )!;
    const mine = SCENARIOS.filter((scenario) => scenario.adversary === capability);

    for (const scenario of mine) await recordRun(scenario.id, "HELD");
    await recordRun(mine[0].id, "FAILED");

    const coverage = (await buildEvaluation(admin)).coverage.find((row) => row.adversary === capability)!;
    expect(coverage.fullyDemonstrated).toBe(false);
  });

  it("counts any run that reported the installation's records as changed", async () => {
    await recordRun(SCENARIOS[0].id, "HELD", { productionUntouched: false });
    expect((await buildEvaluation(admin)).productionTouched).toBe(1);
  });

  it("only covers capabilities the threat model puts in scope", async () => {
    const evaluation = await buildEvaluation(admin);
    // Out-of-scope capabilities have no scenarios and must not appear as gaps to close.
    expect(evaluation.coverage.every((row) => row.capability.length > 0)).toBe(true);
    expect(evaluation.coverage.some((row) => row.adversary === "host-compromise")).toBe(false);
  });

  it("is refused to a role that cannot run the lab", async () => {
    await expect(buildEvaluation(signer)).rejects.toThrow(AuthorizationError);
  });
});
