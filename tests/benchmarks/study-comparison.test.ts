// Cross-run comparison of migration studies: precision as a relative confidence-interval half-width,
// and whether a significant difference found in one run is found, in the same direction, in another.
import { describe, expect, it } from "vitest";
import type { PairwiseComparison } from "@/lib/benchmarks/comparison";
import { agreementOf, directionOf, pairAgreement, relativeHalfWidth } from "@/lib/benchmarks/study-comparison";

function row(a: string, b: string, cliffsDelta: number, significantAt05: boolean): PairwiseComparison {
  return {
    a,
    b,
    medianA: 1,
    medianB: 1,
    ratioOfMedians: 1,
    hodgesLehmann: 0,
    cliffsDelta,
    magnitude: "large",
    mannWhitneyP: significantAt05 ? 0.001 : 0.5,
    mannWhitneyPHolm: significantAt05 ? 0.002 : 0.9,
    welchP: 0.5,
    welchPHolm: 0.9,
    significantAt05,
  } as PairwiseComparison;
}

describe("relative confidence-interval half-width", () => {
  it("is half the interval width over the mean", () => {
    expect(relativeHalfWidth({ meanMs: 10, ci95Ms: [9, 11] })).toBeCloseTo(0.1, 12);
    expect(relativeHalfWidth({ meanMs: 4, ci95Ms: [3.5, 4.3] })).toBeCloseTo(0.1, 12);
  });

  it("is unavailable without an interval or a positive mean", () => {
    expect(relativeHalfWidth({ meanMs: 10, ci95Ms: null })).toBeNull();
    expect(relativeHalfWidth({ meanMs: 0, ci95Ms: [0, 0] })).toBeNull();
  });
});

describe("agreement between runs", () => {
  it("reads the direction from Cliff's delta only when the difference is significant", () => {
    expect(directionOf(row("x", "y", 0.8, true))).toBe("a slower");
    expect(directionOf(row("x", "y", -0.8, true))).toBe("b slower");
    expect(directionOf(row("x", "y", 0.8, false))).toBe("no difference");
  });

  it("classifies the four cases", () => {
    expect(agreementOf(["a slower", "a slower"])).toBe("consistent");
    expect(agreementOf(["a slower", "no difference"])).toBe("partly significant");
    expect(agreementOf(["a slower", "b slower"])).toBe("contradictory");
    expect(agreementOf(["no difference", "no difference"])).toBe("never significant");
  });

  it("matches pairs across runs and skips runs that lack a pair", () => {
    const result = pairAgreement([
      [row("x", "y", 0.9, true), row("x", "z", 0.2, false)],
      [row("x", "y", 0.7, true), row("x", "z", -0.6, true)],
      [row("x", "y", -0.5, true)],
    ]);
    const xy = result.find((pair) => pair.b === "y")!;
    const xz = result.find((pair) => pair.b === "z")!;
    expect(xy).toMatchObject({ runs: 3, significantIn: 3, agreement: "contradictory" });
    expect(xz).toMatchObject({ runs: 2, significantIn: 1, agreement: "partly significant" });
  });
});
