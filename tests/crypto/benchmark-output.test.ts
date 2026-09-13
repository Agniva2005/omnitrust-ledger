// Guards the claim that the /benchmarks page renders measured data: if a benchmark file
// exists, its shape must match what the page reads, its numbers must be real measurements
// rather than placeholders, and its statistics must be internally consistent.
import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { isAlgorithm, orchestrator } from "@/lib/crypto/orchestrator";

const FILE = path.join(process.cwd(), "public", "benchmarks.json");
const data = fs.existsSync(FILE) ? JSON.parse(fs.readFileSync(FILE, "utf8")) : null;
const current = data !== null && data.schemaVersion >= 2;

type Stats = {
  n: number;
  meanMs: number;
  medianMs: number;
  stdDevMs: number;
  standardErrorMs: number;
  ci95Ms: [number, number] | null;
  minMs: number;
  maxMs: number;
  p5Ms: number;
  p95Ms: number;
  coefficientOfVariation: number;
  outliers: number;
};

function expectConsistent(stats: Stats, n: number) {
  expect(stats.n).toBe(n);
  // Real measurements: strictly positive and ordered.
  expect(stats.minMs).toBeGreaterThan(0);
  expect(stats.minMs).toBeLessThanOrEqual(stats.p5Ms);
  expect(stats.p5Ms).toBeLessThanOrEqual(stats.medianMs);
  expect(stats.medianMs).toBeLessThanOrEqual(stats.p95Ms);
  expect(stats.p95Ms).toBeLessThanOrEqual(stats.maxMs);
  expect(stats.meanMs).toBeGreaterThanOrEqual(stats.minMs);
  expect(stats.meanMs).toBeLessThanOrEqual(stats.maxMs);
  expect(stats.stdDevMs).toBeGreaterThanOrEqual(0);
  expect(stats.standardErrorMs).toBeCloseTo(stats.stdDevMs / Math.sqrt(stats.n), 9);
  expect(stats.coefficientOfVariation).toBeCloseTo(stats.stdDevMs / stats.meanMs, 9);
  expect(Number.isInteger(stats.outliers) && stats.outliers >= 0 && stats.outliers <= stats.n).toBe(true);
  if (stats.n >= 2) {
    expect(stats.ci95Ms![0]).toBeLessThanOrEqual(stats.meanMs);
    expect(stats.ci95Ms![1]).toBeGreaterThanOrEqual(stats.meanMs);
  }
}

describe("benchmark output", () => {
  it("is gitignored, so no one else's numbers ship with the repository", () => {
    const gitignore = fs.readFileSync(path.join(process.cwd(), ".gitignore"), "utf8");
    expect(gitignore).toContain("public/benchmarks.json");
    expect(gitignore).toMatch(/^storage\/$/m);
  });

  it.runIf(data !== null)("reports sizes that match each algorithm's declared metadata", () => {
    expect(new Date(data.generatedAt).toString()).not.toBe("Invalid Date");
    for (const entry of data.algorithms) {
      // Results for an algorithm no longer registered say nothing about this build.
      if (!isAlgorithm(entry.algorithm)) continue;
      const { fixedBytes, maxBytes } = orchestrator.describe(entry.algorithm).signature;
      if (fixedBytes !== null) expect(entry.signatureBytes).toBe(fixedBytes);
      expect(entry.signatureBytes).toBeLessThanOrEqual(maxBytes);
    }
  });

  it.runIf(current)("records n, dispersion and a confidence interval that are internally consistent", () => {
    for (const entry of data.algorithms) {
      expectConsistent(entry.keyGeneration, data.parameters.keyGenerationIterations);
      for (const payload of entry.payloads) {
        for (const operation of ["hash", "sign", "verify"] as const) {
          expectConsistent(payload[operation], data.parameters.iterations);
        }
      }
    }
  });

  it.runIf(current)("covers every registered algorithm and records the environment it ran in", () => {
    if (!data.smoke) {
      expect(data.algorithms.map((entry: { algorithm: string }) => entry.algorithm).sort()).toEqual(
        orchestrator.describeAll().map((metadata) => metadata.id).sort(),
      );
    }
    for (const field of ["node", "v8", "openssl", "platform", "arch", "cpu", "cores", "memoryGB"]) {
      expect(data.environment[field]).toBeTruthy();
    }
    expect(data.environment).toHaveProperty("gitCommit");
    expect(data.parameters.warmupIterations).toBeGreaterThan(0);
  });

  it.runIf(current)("states its method and the implementation caveat rather than implying more", () => {
    const methodology = (data.methodology as string[]).join(" ");
    expect(methodology).toMatch(/n - 1/);
    expect(methodology).toMatch(/Tukey/);
    expect(methodology).toMatch(/not removed/);
    const notes = (data.notes as string[]).join(" ");
    expect(notes).toMatch(/@noble\/ed25519/);
    expect(notes).toMatch(/native/i);
    expect(notes).toMatch(/machine/i);
  });
});
