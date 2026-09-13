// Pairwise comparison: every pair once, Holm applied within the operation, and the significance
// call made on the adjusted Mann-Whitney p-value.
import { describe, expect, it } from "vitest";
import { holmAdjust, mannWhitneyU } from "@/lib/benchmarks/inference";
import { pairwiseComparisons } from "@/lib/benchmarks/comparison";

// Deterministic, slightly spread samples: a base pattern shifted by a constant.
const pattern = (offset: number, n = 40) => Array.from({ length: n }, (_, index) => offset + ((index * 17) % 11) / 20);

describe("pairwiseComparisons", () => {
  const groups = { fast: pattern(1), slow: pattern(3), alsoFast: pattern(1) };
  const rows = pairwiseComparisons(groups);

  it("compares each unordered pair exactly once, in input order", () => {
    expect(rows.map((row) => `${row.a}/${row.b}`)).toEqual(["fast/slow", "fast/alsoFast", "slow/alsoFast"]);
  });

  it("reports medians, their ratio and the shift in the samples' unit", () => {
    const [fastSlow] = rows;
    expect(fastSlow.medianB - fastSlow.medianA).toBeCloseTo(2, 12);
    expect(fastSlow.ratioOfMedians).toBeCloseTo(fastSlow.medianA / fastSlow.medianB, 12);
    expect(fastSlow.hodgesLehmann).toBeCloseTo(-2, 12);
    expect(fastSlow.cliffsDelta).toBe(-1);
    expect(fastSlow.magnitude).toBe("large");
  });

  it("applies Holm's correction across the operation's pairs", () => {
    const rawP = rows.map((row) => row.mannWhitneyP);
    expect(rows.map((row) => row.mannWhitneyPHolm)).toEqual(holmAdjust(rawP));
    expect(rows[0].mannWhitneyP).toBe(mannWhitneyU(groups.fast, groups.slow).p);
  });

  it("calls a clear shift significant and identical distributions not significant", () => {
    const byPair = Object.fromEntries(rows.map((row) => [`${row.a}/${row.b}`, row]));
    expect(byPair["fast/slow"].significantAt05).toBe(true);
    expect(byPair["slow/alsoFast"].significantAt05).toBe(true);
    expect(byPair["fast/alsoFast"].significantAt05).toBe(false);
    expect(byPair["fast/alsoFast"].mannWhitneyPHolm).toBe(1);
    expect(byPair["fast/alsoFast"].magnitude).toBe("negligible");
  });
});
