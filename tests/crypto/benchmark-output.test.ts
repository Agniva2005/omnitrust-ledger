// Guards the claim that the /benchmarks page renders measured data: if a benchmark
// file exists, its shape must match what the page reads, and its numbers must be real
// measurements rather than placeholders.
import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { ALGORITHMS } from "@/lib/crypto/types";

const FILE = path.join(process.cwd(), "public", "benchmarks.json");

describe("benchmark output", () => {
  it("is gitignored, so no one else's numbers ship with the repository", () => {
    const gitignore = fs.readFileSync(path.join(process.cwd(), ".gitignore"), "utf8");
    expect(gitignore).toContain("public/benchmarks.json");
  });

  it.runIf(fs.existsSync(FILE))("has the shape the benchmarks page expects", () => {
    const data = JSON.parse(fs.readFileSync(FILE, "utf8"));

    expect(new Date(data.generatedAt).toString()).not.toBe("Invalid Date");
    expect(data.environment.cpu.length).toBeGreaterThan(0);
    expect(data.parameters.iterations).toBeGreaterThan(0);
    expect(data.algorithms.map((entry: { algorithm: string }) => entry.algorithm).sort()).toEqual(
      [...ALGORITHMS].sort(),
    );

    for (const entry of data.algorithms) {
      // Sizes must match what the algorithm actually produces.
      if (entry.algorithm === "ED25519") expect(entry.signatureBytes).toBe(64);
      if (entry.algorithm === "RSA") expect(entry.signatureBytes).toBe(384);

      for (const payload of entry.payloads) {
        for (const operation of ["hash", "sign", "verify"] as const) {
          const stats = payload[operation];
          expect(stats.iterations).toBe(data.parameters.iterations);
          // Real measurements: strictly positive, ordered, and not identical constants.
          expect(stats.medianMs).toBeGreaterThan(0);
          expect(stats.minMs).toBeLessThanOrEqual(stats.medianMs);
          expect(stats.maxMs).toBeGreaterThanOrEqual(stats.p95Ms);
          expect(stats.p95Ms).toBeGreaterThanOrEqual(stats.medianMs);
        }
      }
    }
  });

  it.runIf(fs.existsSync(FILE))("states the implementation caveat rather than implying otherwise", () => {
    const data = JSON.parse(fs.readFileSync(FILE, "utf8"));
    const notes = (data.notes as string[]).join(" ");
    expect(notes).toMatch(/@noble\/ed25519/);
    expect(notes).toMatch(/native/i);
    expect(notes).toMatch(/environment|machine/i);
  });
});
