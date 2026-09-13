// Inferential statistics, checked against closed forms and values computed by hand rather than
// against other software's output: Student's t with 1 and 2 degrees of freedom has an elementary
// distribution function, and small samples make U, Cliff's delta and Holm's adjustment countable.
import { describe, expect, it } from "vitest";
import {
  cliffMagnitude,
  holmAdjust,
  logGamma,
  mannWhitneyU,
  normalCdf,
  normalUpperTail,
  regularizedIncompleteBeta,
  studentTTwoSidedP,
  welchTTest,
} from "@/lib/benchmarks/inference";

describe("special functions", () => {
  it("logGamma matches exact values of the gamma function", () => {
    expect(logGamma(1)).toBeCloseTo(0, 12);
    expect(logGamma(5)).toBeCloseTo(Math.log(24), 12);
    expect(logGamma(0.5)).toBeCloseTo(0.5 * Math.log(Math.PI), 12);
    expect(logGamma(10.5)).toBeCloseTo(Math.log(1133278.3889487855), 9);
    expect(() => logGamma(0)).toThrow(RangeError);
  });

  it("the regularised incomplete beta function satisfies its closed forms", () => {
    // I_x(1, 1) = x, I_x(a, 1) = x^a, I_x(1, b) = 1 - (1 - x)^b.
    for (const x of [0.1, 0.37, 0.5, 0.9]) {
      expect(regularizedIncompleteBeta(x, 1, 1)).toBeCloseTo(x, 12);
      expect(regularizedIncompleteBeta(x, 3, 1)).toBeCloseTo(x ** 3, 12);
      expect(regularizedIncompleteBeta(x, 1, 4)).toBeCloseTo(1 - (1 - x) ** 4, 12);
      // Symmetry: I_x(a, b) = 1 - I_{1-x}(b, a).
      expect(regularizedIncompleteBeta(x, 2.5, 7)).toBeCloseTo(1 - regularizedIncompleteBeta(1 - x, 7, 2.5), 12);
    }
    expect(regularizedIncompleteBeta(0, 2, 3)).toBe(0);
    expect(regularizedIncompleteBeta(1, 2, 3)).toBe(1);
  });

  it("Student's t two-sided p-value equals the closed forms for 1 and 2 degrees of freedom", () => {
    for (const t of [0, 0.5, 1, 2.3, -3.7, 12]) {
      // df = 1 (Cauchy): P(|T| > t) = 1 - 2·atan(|t|)/π.
      expect(studentTTwoSidedP(t, 1)).toBeCloseTo(1 - (2 * Math.atan(Math.abs(t))) / Math.PI, 10);
      // df = 2: P(|T| > t) = 1 - |t| / sqrt(t² + 2).
      expect(studentTTwoSidedP(t, 2)).toBeCloseTo(1 - Math.abs(t) / Math.sqrt(t * t + 2), 10);
    }
  });

  it("Student's t approaches the normal distribution for large degrees of freedom", () => {
    expect(studentTTwoSidedP(1.96, 1e7)).toBeCloseTo(2 * (1 - normalCdf(1.96)), 5);
  });

  it("the normal distribution function matches known quantiles to 12 digits, on both sides of the series/fraction switch", () => {
    expect(normalCdf(0)).toBe(0.5);
    expect(normalCdf(1.959963984540054)).toBeCloseTo(0.975, 12);
    expect(normalCdf(-1.959963984540054)).toBeCloseTo(0.025, 12);
    expect(normalCdf(3)).toBeCloseTo(0.9986501019683699, 12);
    // z = 5 lies beyond the switch (5/√2 > 3): Q(5) = 2.866515718791939e-7.
    expect(normalUpperTail(5) / 2.866515718791939e-7).toBeCloseTo(1, 10);
    expect(normalCdf(-5) / 2.866515718791939e-7).toBeCloseTo(1, 10);
    // Continuity at the switch point z = 3√2.
    expect(normalUpperTail(3 * Math.SQRT2 - 1e-9)).toBeCloseTo(normalUpperTail(3 * Math.SQRT2 + 1e-9), 12);
  });
});

describe("Welch's t-test", () => {
  it("matches a hand computation of t and the Welch-Satterthwaite degrees of freedom", () => {
    // x: mean 3, variance 2.5; y: mean 6, variance 10; n = 5 each.
    const result = welchTTest([1, 2, 3, 4, 5], [2, 4, 6, 8, 10]);
    const se2 = 2.5 / 5 + 10 / 5;
    expect(result.meanDifference).toBe(-3);
    expect(result.t).toBeCloseTo(-3 / Math.sqrt(se2), 12);
    expect(result.degreesOfFreedom).toBeCloseTo(se2 ** 2 / ((2.5 / 5) ** 2 / 4 + (10 / 5) ** 2 / 4), 12);
    expect(result.p).toBeCloseTo(studentTTwoSidedP(result.t, result.degreesOfFreedom), 12);
    expect(result.p).toBeGreaterThan(0.05);
  });

  it("is symmetric in its arguments and gives p = 1 for identical samples", () => {
    const a = [5.1, 4.9, 5.3, 5.0, 5.2];
    const b = [6.0, 6.4, 5.8, 6.1, 6.2];
    expect(welchTTest(a, b).p).toBeCloseTo(welchTTest(b, a).p, 12);
    expect(welchTTest(a, b).t).toBeCloseTo(-welchTTest(b, a).t, 12);
    expect(welchTTest(a, [...a]).p).toBeCloseTo(1, 12);
  });

  it("refuses samples too small to have a variance", () => {
    expect(() => welchTTest([1], [2, 3])).toThrow(RangeError);
  });
});

describe("Mann-Whitney U, Cliff's delta and the Hodges-Lehmann shift", () => {
  it("counts U and the shift for completely separated samples", () => {
    const result = mannWhitneyU([1, 2, 3], [4, 5, 6]);
    expect(result.u).toBe(0);
    expect(result.cliffsDelta).toBe(-1);
    expect(result.magnitude).toBe("large");
    // Pairwise differences x - y: -3,-4,-5,-2,-3,-4,-1,-2,-3; their median is -3.
    expect(result.hodgesLehmann).toBe(-3);
  });

  it("counts ties as one half", () => {
    // Pairs: (1,2)< (1,3)< (2,2)= (2,3)< (2,2)= (2,3)<, so U = 0 + 2 × 0.5 = 1 and δ = 2·1/6 − 1.
    const result = mannWhitneyU([1, 2, 2], [2, 3]);
    expect(result.u).toBe(1);
    expect(result.cliffsDelta).toBeCloseTo(-2 / 3, 12);
  });

  it("gives z = 0 and p = 1 for identical samples, and a tiny p for a clear shift", () => {
    const base = Array.from({ length: 50 }, (_, index) => 10 + ((index * 7) % 13) / 10);
    const same = mannWhitneyU(base, [...base]);
    expect(same.z).toBe(0);
    expect(same.p).toBe(1);
    expect(same.cliffsDelta).toBe(0);

    const shifted = mannWhitneyU(base, base.map((value) => value + 5));
    expect(shifted.p).toBeLessThan(1e-9);
    expect(shifted.cliffsDelta).toBe(-1);
    expect(shifted.hodgesLehmann).toBeCloseTo(-5, 12);
  });

  it("applies Romano et al.'s magnitude thresholds", () => {
    expect(cliffMagnitude(0.1)).toBe("negligible");
    expect(cliffMagnitude(-0.2)).toBe("small");
    expect(cliffMagnitude(0.4)).toBe("medium");
    expect(cliffMagnitude(-0.9)).toBe("large");
  });
});

describe("Holm's step-down correction", () => {
  it("matches a hand computation and keeps the input order", () => {
    // Sorted 0.01, 0.03, 0.04 → 3×0.01 = 0.03, 2×0.03 = 0.06, max(0.06, 1×0.04) = 0.06.
    const adjusted = holmAdjust([0.01, 0.04, 0.03]);
    expect(adjusted[0]).toBeCloseTo(0.03, 12);
    expect(adjusted[1]).toBeCloseTo(0.06, 12);
    expect(adjusted[2]).toBeCloseTo(0.06, 12);
  });

  it("never exceeds 1 and never decreases the raw p-values", () => {
    const raw = [0.5, 0.2, 0.9, 0.001];
    const adjusted = holmAdjust(raw);
    adjusted.forEach((value, index) => {
      expect(value).toBeLessThanOrEqual(1);
      expect(value).toBeGreaterThanOrEqual(raw[index]);
    });
  });
});
