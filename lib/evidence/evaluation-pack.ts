// The adversarial evaluation as a takeaway artefact.
//
// A reviewer cannot be asked to click through sixteen scenarios. This writes the matrix, the
// coverage argument and the threat model's own adversary list into one archive, with a README
// saying plainly what the numbers do and do not establish.
import { appendAuditEntry } from "@/lib/audit/log";
import { requireCapability, type Actor } from "@/lib/auth/rbac";
import { sha256Hex } from "@/lib/crypto/hash";
import { createZip, type ZipEntry } from "@/lib/evidence/zip";
import { ADVERSARIES } from "@/lib/security-lab/catalog";
import { buildEvaluation } from "@/lib/security-lab/evaluation";

function readme(totals: { scenarios: number; held: number; failed: number; errored: number; neverRun: number }, untouched: boolean, builtAt: string): string {
  return `OmniTrust Ledger — adversarial evaluation
=========================================

Scenarios      ${totals.scenarios}
Controls held  ${totals.held}
Failed         ${totals.failed}
Errored        ${totals.errored}
Never run here ${totals.neverRun}
Records        ${untouched ? "this installation's own records unchanged by every recorded run" : "AT LEAST ONE RUN REPORTED THIS INSTALLATION'S RECORDS AS CHANGED"}
Built          ${builtAt}

Contents
--------
  evaluation.json  every scenario, its adversary capability, the control, the expected
                   result, and the outcome of the most recent real run on this machine
  adversaries.json the threat model's capability list, in scope and out
  README.txt       this description

What these numbers mean
-----------------------
Each scenario is a real attack executed against real services in a throwaway sandbox with
its own database, storage and keys, which is deleted afterwards. "HELD" means the control
produced the stated result; it is an observation, not a proof.

Each result is read back out of this installation's hash-chained audit log, and every row
carries the sequence number and hash of the entry it came from. That means the evaluation
can be checked the same way a document can: walk the chain, find the entry, compare.

What they do not mean
---------------------
A capability marked demonstrated shows that the scenarios written for it held on this
machine. It does not show the scenario set is complete, and it says nothing about the
capabilities the threat model places out of scope — those are listed in adversaries.json
with the consequence each would have, and none of them is defended against.

A scenario marked "never run here" is exactly that. It is not a pass.
`;
}

export type EvaluationPack = { filename: string; bytes: Buffer; held: number; scenarios: number };

export async function buildEvaluationPack(actor: Actor): Promise<EvaluationPack> {
  requireCapability(actor, "lab:run");

  const evaluation = await buildEvaluation(actor);
  const builtAt = new Date();

  const entries: ZipEntry[] = [
    { name: "evaluation.json", data: Buffer.from(JSON.stringify(evaluation, null, 2), "utf8") },
    { name: "adversaries.json", data: Buffer.from(JSON.stringify(ADVERSARIES, null, 2), "utf8") },
    {
      name: "README.txt",
      data: Buffer.from(readme(evaluation.totals, evaluation.productionTouched === 0, builtAt.toISOString()), "utf8"),
    },
  ];

  const bytes = createZip(entries, builtAt);

  await appendAuditEntry({
    actorUserId: actor.userId,
    action: "EVIDENCE_PACK_BUILT",
    targetType: "SecurityLabEvaluation",
    targetId: String(evaluation.totals.scenarios),
    metadata: { held: evaluation.totals.held, neverRun: evaluation.totals.neverRun, packSha256: sha256Hex(bytes) },
  });

  return { filename: `omnitrust-evaluation-${builtAt.toISOString().slice(0, 10)}.zip`, bytes, held: evaluation.totals.held, scenarios: evaluation.totals.scenarios };
}
