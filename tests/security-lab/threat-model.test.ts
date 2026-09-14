// The threat model and the Security Lab must describe the same thing: every scenario uses an
// in-scope adversary capability, every in-scope capability is tested by at least one scenario,
// every out-of-scope capability says what it could achieve, and docs/threat-model.md names every
// scenario and every capability.
import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { ADVERSARIES, SCENARIOS, adversaryFor } from "@/lib/security-lab/catalog";

const THREAT_MODEL = fs.readFileSync(path.join(process.cwd(), "docs", "threat-model.md"), "utf8");

describe("the threat model", () => {
  it("assigns every scenario an in-scope adversary capability", () => {
    for (const scenario of SCENARIOS) {
      expect(adversaryFor(scenario.adversary).inScope, scenario.id).toBe(true);
    }
  });

  it("tests every in-scope capability with at least one scenario", () => {
    for (const adversary of ADVERSARIES.filter((candidate) => candidate.inScope)) {
      expect(SCENARIOS.some((scenario) => scenario.adversary === adversary.id), adversary.id).toBe(true);
    }
  });

  it("states the consequence of every capability it does not defend against", () => {
    for (const adversary of ADVERSARIES.filter((candidate) => !candidate.inScope)) {
      expect(adversary.consequence?.length ?? 0, adversary.id).toBeGreaterThan(20);
    }
  });

  it("names every scenario and every capability in docs/threat-model.md", () => {
    for (const scenario of SCENARIOS) expect(THREAT_MODEL, scenario.id).toContain(`\`${scenario.id}\``);
    for (const adversary of ADVERSARIES) expect(THREAT_MODEL, adversary.id).toContain(`\`${adversary.id}\``);
  });
});
