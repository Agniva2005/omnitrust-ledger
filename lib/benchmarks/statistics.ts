// Descriptive statistics for benchmark samples. Pure functions with no dependencies, so every
// definition can be tested against hand-computed values.
//
// Definitions, stated so results can be reproduced elsewhere:
// - standard deviation is the sample standard deviation (divisor n - 1);
// - percentiles use linear interpolation between order statistics (Hyndman & Fan type 7, the
//   default in NumPy and R), and the median is the 50th percentile;
// - the 95% confidence interval is for the mean, mean ± t(0.975, n - 1) × s / √n. The t
//   quantile comes from a table; between tabulated degrees of freedom the next lower entry is
//   used, which gives a slightly wider (conservative) interval;
// - outliers are counted with Tukey's fences, Q1 - 1.5·IQR and Q3 + 1.5·IQR. They are reported,
//   never removed.
//
// The confidence interval assumes samples are independent and their mean roughly normal. Timing
// samples are neither strictly independent (warm caches, garbage collection) nor normal (long
// right tails), so the median and the outlier count are reported alongside it.

/** Two-sided 95% critical values of Student's t, keyed by degrees of freedom. */
const T_975: readonly [number, number][] = [
  [1, 12.706], [2, 4.303], [3, 3.182], [4, 2.776], [5, 2.571], [6, 2.447], [7, 2.365], [8, 2.306],
  [9, 2.262], [10, 2.228], [11, 2.201], [12, 2.179], [13, 2.16], [14, 2.145], [15, 2.131], [16, 2.12],
  [17, 2.11], [18, 2.101], [19, 2.093], [20, 2.086], [21, 2.08], [22, 2.074], [23, 2.069], [24, 2.064],
  [25, 2.06], [26, 2.056], [27, 2.052], [28, 2.048], [29, 2.045], [30, 2.042], [40, 2.021], [50, 2.009],
  [60, 2.0], [80, 1.99], [100, 1.984], [120, 1.98],
];
const Z_975 = 1.96;

/** t(0.975, df), conservative between tabulated values; the normal value beyond df = 120 would understate it, so 120's entry is kept until df reaches 1000. */
export function tCritical95(degreesOfFreedom: number): number {
  if (!Number.isInteger(degreesOfFreedom) || degreesOfFreedom < 1) {
    throw new RangeError("Degrees of freedom must be a positive integer");
  }
  if (degreesOfFreedom >= 1000) return Z_975;
  let value = T_975[0][1];
  for (const [df, critical] of T_975) {
    if (df <= degreesOfFreedom) value = critical;
  }
  return value;
}

export function mean(values: readonly number[]): number {
  if (values.length === 0) throw new RangeError("mean of an empty sample");
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

/** Sample standard deviation (n - 1). Zero for a single value. */
export function sampleStandardDeviation(values: readonly number[]): number {
  if (values.length === 0) throw new RangeError("standard deviation of an empty sample");
  if (values.length === 1) return 0;
  const average = mean(values);
  const squares = values.reduce((sum, value) => sum + (value - average) ** 2, 0);
  return Math.sqrt(squares / (values.length - 1));
}

/** Hyndman & Fan type 7 percentile, p in [0, 100]. */
export function percentile(values: readonly number[], p: number): number {
  if (values.length === 0) throw new RangeError("percentile of an empty sample");
  if (p < 0 || p > 100) throw new RangeError("percentile must be between 0 and 100");
  const sorted = [...values].sort((a, b) => a - b);
  const position = (sorted.length - 1) * (p / 100);
  const lower = Math.floor(position);
  const upper = Math.ceil(position);
  return sorted[lower] + (position - lower) * (sorted[upper] - sorted[lower]);
}

export function median(values: readonly number[]): number {
  return percentile(values, 50);
}

export type SampleSummary = {
  n: number;
  meanMs: number;
  medianMs: number;
  stdDevMs: number;
  standardErrorMs: number;
  /** 95% confidence interval for the mean, or null with fewer than two samples. */
  ci95Ms: [number, number] | null;
  minMs: number;
  maxMs: number;
  p5Ms: number;
  p95Ms: number;
  /** Standard deviation divided by the mean. */
  coefficientOfVariation: number;
  /** Samples outside Tukey's fences. Reported, not removed. */
  outliers: number;
};

export function summarise(samplesMs: readonly number[]): SampleSummary {
  if (samplesMs.length === 0) throw new RangeError("cannot summarise an empty sample");
  const n = samplesMs.length;
  const average = mean(samplesMs);
  const stdDev = sampleStandardDeviation(samplesMs);
  const standardError = stdDev / Math.sqrt(n);
  const halfWidth = n >= 2 ? tCritical95(n - 1) * standardError : null;

  const q1 = percentile(samplesMs, 25);
  const q3 = percentile(samplesMs, 75);
  const iqr = q3 - q1;
  const outliers = samplesMs.filter((value) => value < q1 - 1.5 * iqr || value > q3 + 1.5 * iqr).length;

  return {
    n,
    meanMs: average,
    medianMs: median(samplesMs),
    stdDevMs: stdDev,
    standardErrorMs: standardError,
    ci95Ms: halfWidth === null ? null : [average - halfWidth, average + halfWidth],
    minMs: Math.min(...samplesMs),
    maxMs: Math.max(...samplesMs),
    p5Ms: percentile(samplesMs, 5),
    p95Ms: percentile(samplesMs, 95),
    coefficientOfVariation: average === 0 ? 0 : stdDev / average,
    outliers,
  };
}
