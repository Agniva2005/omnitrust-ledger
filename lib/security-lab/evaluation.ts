// The adversarial evaluation, assembled from the audit log.
//
// Every Security Lab run already appends an audit entry carrying its outcome, its duration and
// whether the application's own records were untouched. Reading the evaluation back out of that
// log rather than keeping a second table is deliberate: the results are then protected by the
// same hash chain and signed checkpoints the system is arguing for, so a claim about the
// evaluation can be checked the same way a claim about a document is.
//
// Nothing here re-runs anything or infers a result. A scenario that has never been run says so.
import { ADVERSARIES, SCENARIOS, adversaryFor, type AdversaryId, type ScenarioDefinition } from "@/lib/security-lab/catalog";
import { requireCapability, type Actor } from "@/lib/auth/rbac";
import { prisma } from "@/lib/db";

export type ScenarioOutcome = "HELD" | "FAILED" | "ERROR";

export type ScenarioResultRow = {
  scenario: ScenarioDefinition;
  adversaryLabel: string;
  /** The most recent real run, or null where the scenario has never been run here. */
  latest: {
    outcome: ScenarioOutcome;
    at: string;
    durationMs: number | null;
    productionUntouched: boolean | null;
    subjectFilename: string | null;
    /** The audit entry this result comes from, so it can be found and checked. */
    auditSeq: number;
    auditHash: string;
  } | null;
  runCount: number;
};

export type CoverageRow = {
  adversary: AdversaryId;
  label: string;
  capability: string;
  scenarios: number;
  run: number;
  held: number;
  /** Every scenario for this capability has been run and every one held. */
  fullyDemonstrated: boolean;
};

export type Evaluation = {
  rows: ScenarioResultRow[];
  coverage: CoverageRow[];
  totals: { scenarios: number; run: number; held: number; failed: number; errored: number; neverRun: number };
  /** Runs that reported the application's own records as changed: should always be zero. */
  productionTouched: number;
  generatedAt: string;
};

type Metadata = Record<string, unknown>;

const isOutcome = (value: unknown): value is ScenarioOutcome =>
  value === "HELD" || value === "FAILED" || value === "ERROR";

export async function buildEvaluation(actor: Actor): Promise<Evaluation> {
  requireCapability(actor, "lab:run");

  const entries = await prisma.auditLogEntry.findMany({
    where: { action: "SECURITY_LAB_RUN" },
    orderBy: { seq: "desc" },
  });

  const latestByScenario = new Map<string, ScenarioResultRow["latest"]>();
  const countByScenario = new Map<string, number>();
  let productionTouched = 0;

  for (const entry of entries) {
    countByScenario.set(entry.targetId, (countByScenario.get(entry.targetId) ?? 0) + 1);

    let metadata: Metadata = {};
    try {
      metadata = JSON.parse(entry.metadataJson) as Metadata;
    } catch {
      metadata = {};
    }
    if (metadata.productionUntouched === false) productionTouched += 1;

    // Entries are newest first, so the first one seen for a scenario is its latest run.
    if (latestByScenario.has(entry.targetId)) continue;
    if (!isOutcome(metadata.outcome)) continue;

    latestByScenario.set(entry.targetId, {
      outcome: metadata.outcome,
      at: entry.createdAt.toISOString(),
      durationMs: typeof metadata.durationMs === "number" ? metadata.durationMs : null,
      productionUntouched: typeof metadata.productionUntouched === "boolean" ? metadata.productionUntouched : null,
      subjectFilename: typeof metadata.subjectFilename === "string" ? metadata.subjectFilename : null,
      auditSeq: entry.seq,
      auditHash: entry.entryHash,
    });
  }

  const rows: ScenarioResultRow[] = SCENARIOS.map((scenario) => ({
    scenario,
    adversaryLabel: adversaryFor(scenario.adversary).label,
    latest: latestByScenario.get(scenario.id) ?? null,
    runCount: countByScenario.get(scenario.id) ?? 0,
  }));

  const coverage: CoverageRow[] = ADVERSARIES.filter((adversary) => adversary.inScope).map((adversary) => {
    const mine = rows.filter((row) => row.scenario.adversary === adversary.id);
    const run = mine.filter((row) => row.latest !== null);
    const held = run.filter((row) => row.latest?.outcome === "HELD");
    return {
      adversary: adversary.id,
      label: adversary.label,
      capability: adversary.capability,
      scenarios: mine.length,
      run: run.length,
      held: held.length,
      fullyDemonstrated: mine.length > 0 && run.length === mine.length && held.length === mine.length,
    };
  });

  const outcomes = rows.map((row) => row.latest?.outcome ?? null);
  return {
    rows,
    coverage,
    totals: {
      scenarios: rows.length,
      run: outcomes.filter((outcome) => outcome !== null).length,
      held: outcomes.filter((outcome) => outcome === "HELD").length,
      failed: outcomes.filter((outcome) => outcome === "FAILED").length,
      errored: outcomes.filter((outcome) => outcome === "ERROR").length,
      neverRun: outcomes.filter((outcome) => outcome === null).length,
    },
    productionTouched,
    generatedAt: new Date().toISOString(),
  };
}
