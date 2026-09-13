// The local CI plan. Running CI inside the test suite would be recursive, so this checks the plan
// itself: every test file is in exactly one suite, every step's program exists, and the gates run
// before the build. `npm run ci` is the real run.
import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { TEST_SUITES, ciSteps } from "@/scripts/ci";

const ROOT = process.cwd();

function testFiles(directory: string): string[] {
  const found: string[] = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) found.push(...testFiles(full));
    else if (entry.name.endsWith(".test.ts")) found.push(path.relative(ROOT, full).split(path.sep).join("/"));
  }
  return found;
}

describe("the CI plan", () => {
  it("puts every test file in exactly one suite, and every suite entry exists", () => {
    const entries = Object.values(TEST_SUITES).flat();
    for (const entry of entries) expect(fs.existsSync(path.join(ROOT, entry)), entry).toBe(true);

    for (const file of testFiles(path.join(ROOT, "tests"))) {
      const owners = entries.filter((entry) => file === entry || file.startsWith(`${entry}/`));
      expect(owners, `${file} belongs to ${owners.length} suites`).toHaveLength(1);
    }
  });

  it("starts every step with a program that exists", () => {
    for (const step of ciSteps()) {
      if (step.unavailable) continue;
      expect(step.command[0]).toBe(process.execPath);
      expect(fs.existsSync(step.command[1]), `${step.id}: ${step.command[1]}`).toBe(true);
    }
  });

  it("runs the static gates and all three test suites before the build and the benchmark smoke run", () => {
    const order = ciSteps().map((step) => step.id);
    expect(order).toEqual(
      expect.arrayContaining(["dependencies", "prisma-schema", "contract-artifact", "lint", "typecheck", "crypto-boundary", "tests-unit", "tests-integration", "tests-security", "build", "benchmark-smoke"]),
    );
    for (const gate of ["typecheck", "crypto-boundary", "tests-unit", "tests-integration", "tests-security"]) {
      expect(order.indexOf(gate)).toBeLessThan(order.indexOf("build"));
    }
    expect(order.at(-1)).toBe("benchmark-smoke");
  });

  it("is what `npm run ci` runs, and writes its reports where git ignores them", () => {
    const scripts = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8")).scripts;
    expect(scripts.ci).toBe("tsx scripts/ci.ts");
    expect(fs.readFileSync(path.join(ROOT, ".gitignore"), "utf8")).toMatch(/^storage\/$/m);
  });
});
