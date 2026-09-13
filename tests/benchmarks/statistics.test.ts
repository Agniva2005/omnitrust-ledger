// Benchmark statistics, checked against values computed by hand (and matching NumPy's defaults
// for percentiles and ddof=1 standard deviation).
import { describe, expect, it } from "vitest";
import {
  mean,
  median,
  percentile,
  sampleStandardDeviation,
  summarise,
  tCritical95,
} from "@/lib/benchmarks/statistics";

const TEXTBOOK = [2, 4, 4, 4, 5, 5, 7, 9];

describe("descriptive statistics", () => {
  it("computes the mean and the sample (n - 1) standard deviation", () => {
    expect(mean(TEXTBOOK)).toBe(5);
    // Population SD of this classic sample is exactly 2; the sample SD is sqrt(32 / 7).
    expect(sampleStandardDeviation(TEXTBOOK)).toBeCloseTo(Math.sqrt(32 / 7), 12);
    expect(sampleStandardDeviation([3])).toBe(0);
  });

  it("interpolates percentiles as Hyndman & Fan type 7", () => {
    expect(median(TEXTBOOK)).toBe(4.5);
    expect(percentile(TEXTBOOK, 25)).toBe(4);
    expect(percentile(TEXTBOOK, 75)).toBe(5.5);
    expect(percentile([1, 2, 3, 4], 95)).toBeCloseTo(3.85, 12);
    expect(percentile([10], 95)).toBe(10);
    expect(median([5, 1, 3])).toBe(3);
  });

  it("does not depend on input order and does not mutate the input", () => {
    const shuffled = [9, 2, 5, 4, 7, 4, 5, 4];
    expect(percentile(shuffled, 75)).toBe(5.5);
    expect(shuffled).toEqual([9, 2, 5, 4, 7, 4, 5, 4]);
  });

  it("rejects empty samples and out-of-range percentiles", () => {
    expect(() => mean([])).toThrow(RangeError);
    expect(() => summarise([])).toThrow(RangeError);
    expect(() => percentile(TEXTBOOK, 101)).toThrow(RangeError);
  });
});

describe("the 95% confidence interval", () => {
  it("uses tabulated t quantiles, conservatively between entries", () => {
    expect(tCritical95(1)).toBe(12.706);
    expect(tCritical95(9)).toBe(2.262);
    expect(tCritical95(29)).toBe(2.045);
    // df 45 falls between 40 and 50: the df 40 value (larger, so a wider interval) is used.
    expect(tCritical95(45)).toBe(2.021);
    expect(tCritical95(199)).toBe(1.98);
    expect(tCritical95(5000)).toBe(1.96);
    expect(() => tCritical95(0)).toThrow(RangeError);
  });

  it("matches a hand computation for 1..10", () => {
    const summary = summarise([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    const standardError = Math.sqrt(55 / 6) / Math.sqrt(10);
    expect(summary.n).toBe(10);
    expect(summary.meanMs).toBe(5.5);
    expect(summary.standardErrorMs).toBeCloseTo(standardError, 12);
    expect(summary.ci95Ms![0]).toBeCloseTo(5.5 - 2.262 * standardError, 12);
    expect(summary.ci95Ms![1]).toBeCloseTo(5.5 + 2.262 * standardError, 12);
  });

  it("is null for a single sample rather than a fabricated interval", () => {
    expect(summarise([4.2]).ci95Ms).toBeNull();
  });
});

describe("outliers", () => {
  it("counts values outside Tukey's fences without removing them", () => {
    const summary = summarise([1, 2, 3, 4, 100]);
    expect(summary.outliers).toBe(1);
    expect(summary.maxMs).toBe(100);
    expect(summary.meanMs).toBe(22);
    // Q1 = 4, Q3 = 5.5, IQR = 1.5: the upper fence is 7.75, so 9 is an outlier and 7 is not.
    expect(summarise(TEXTBOOK).outliers).toBe(1);
    expect(summarise([2, 4, 4, 4, 5, 5, 7, 7.5]).outliers).toBe(0);
  });

  it("reports the coefficient of variation", () => {
    expect(summarise(TEXTBOOK).coefficientOfVariation).toBeCloseTo(Math.sqrt(32 / 7) / 5, 12);
  });
});
