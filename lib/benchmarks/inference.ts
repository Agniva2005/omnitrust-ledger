// Inferential statistics for comparing benchmark samples between algorithms. Pure functions with no
// dependencies, tested against closed forms and hand-computed values.
//
// Why these tests. Timing samples have long right tails and are not normal, so the primary
// comparison is non-parametric: the Mann-Whitney U test (is one algorithm's timing
// distribution shifted relative to another's?) with Cliff's delta as its effect size and the
// Hodges-Lehmann estimator as the shift in milliseconds. Welch's t-test on the means is reported
// alongside, because reviewers expect it, but it is secondary. With several algorithms every
// pairwise comparison is corrected with Holm's step-down method, which controls the family-wise
// error rate without assuming independence between comparisons.
//
// Definitions:
// - Mann-Whitney U uses average ranks for ties, the tie-corrected variance
//   n1·n2/12 · ((n + 1) − Σ(t³ − t) / (n(n − 1))), a continuity correction of 0.5, and the
//   normal approximation, which is appropriate for the sample sizes used here (n ≥ 20 per group);
// - Cliff's delta is P(X > Y) − P(X < Y) = 2·U_X / (n1·n2) − 1, with Romano et al. (2006)
//   magnitude thresholds 0.147, 0.33 and 0.474;
// - the Hodges-Lehmann estimate is the median of all pairwise differences x − y;
// - Welch's t uses the Welch-Satterthwaite degrees of freedom, and its p-value comes from the
//   Student t distribution through the regularised incomplete beta function;
// - the normal distribution uses erf's Maclaurin series for |z/√2| < 3 and erfc's continued fraction
//   beyond, and tail probabilities are computed directly so very small p-values keep their precision.

// ---------------------------------------------------------------------------------------------
// Special functions
// ---------------------------------------------------------------------------------------------

const LANCZOS = [
  0.99999999999980993, 676.5203681218851, -1259.1392167224028, 771.32342877765313, -176.61502916214059,
  12.507343278686905, -0.13857109526572012, 9.9843695780195716e-6, 1.5056327351493116e-7,
];

/** Natural logarithm of the gamma function for x > 0 (Lanczos approximation, g = 7). */
export function logGamma(x: number): number {
  if (!(x > 0)) throw new RangeError("logGamma is defined here for x > 0");
  if (x < 0.5) return Math.log(Math.PI / Math.sin(Math.PI * x)) - logGamma(1 - x);
  const z = x - 1;
  let sum = LANCZOS[0];
  for (let index = 1; index < LANCZOS.length; index += 1) sum += LANCZOS[index] / (z + index);
  const t = z + 7.5;
  return 0.5 * Math.log(2 * Math.PI) + (z + 0.5) * Math.log(t) - t + Math.log(sum);
}

/** Continued fraction for the incomplete beta function (modified Lentz's method). */
function betaContinuedFraction(x: number, a: number, b: number): number {
  const TINY = 1e-300;
  const EPSILON = 1e-15;
  let c = 1;
  let d = 1 - ((a + b) * x) / (a + 1);
  if (Math.abs(d) < TINY) d = TINY;
  d = 1 / d;
  let result = d;
  for (let m = 1; m <= 10_000; m += 1) {
    const m2 = 2 * m;
    let numerator = (m * (b - m) * x) / ((a + m2 - 1) * (a + m2));
    d = 1 + numerator * d;
    if (Math.abs(d) < TINY) d = TINY;
    c = 1 + numerator / c;
    if (Math.abs(c) < TINY) c = TINY;
    d = 1 / d;
    result *= d * c;

    numerator = (-(a + m) * (a + b + m) * x) / ((a + m2) * (a + m2 + 1));
    d = 1 + numerator * d;
    if (Math.abs(d) < TINY) d = TINY;
    c = 1 + numerator / c;
    if (Math.abs(c) < TINY) c = TINY;
    d = 1 / d;
    const delta = d * c;
    result *= delta;
    if (Math.abs(delta - 1) < EPSILON) return result;
  }
  throw new Error("incomplete beta continued fraction did not converge");
}

/** Regularised incomplete beta function I_x(a, b) for 0 ≤ x ≤ 1 and a, b > 0. */
export function regularizedIncompleteBeta(x: number, a: number, b: number): number {
  if (!(a > 0 && b > 0)) throw new RangeError("a and b must be positive");
  if (x < 0 || x > 1 || Number.isNaN(x)) throw new RangeError("x must lie in [0, 1]");
  if (x === 0 || x === 1) return x;
  const logFront = logGamma(a + b) - logGamma(a) - logGamma(b) + a * Math.log(x) + b * Math.log(1 - x);
  const front = Math.exp(logFront);
  // The continued fraction converges fastest on the side of the mean; use the symmetry relation otherwise.
  return x < (a + 1) / (a + b + 2)
    ? (front * betaContinuedFraction(x, a, b)) / a
    : 1 - (front * betaContinuedFraction(1 - x, b, a)) / b;
}

/** Two-sided p-value of Student's t statistic with (possibly non-integer) degrees of freedom. */
export function studentTTwoSidedP(t: number, degreesOfFreedom: number): number {
  if (!(degreesOfFreedom > 0)) throw new RangeError("degrees of freedom must be positive");
  if (!Number.isFinite(t)) return Number.isNaN(t) ? Number.NaN : 0;
  return regularizedIncompleteBeta(degreesOfFreedom / (degreesOfFreedom + t * t), degreesOfFreedom / 2, 0.5);
}

/** erf(x) by its Maclaurin series; accurate to about 1e-14 for |x| < 3, and exactly 0 at 0. */
function erfSeries(x: number): number {
  let term = x;
  let sum = x;
  for (let n = 1; n < 200; n += 1) {
    term *= (-x * x) / n;
    const contribution = term / (2 * n + 1);
    sum += contribution;
    if (Math.abs(contribution) < 1e-17 * Math.abs(sum)) break;
  }
  return (2 / Math.sqrt(Math.PI)) * sum;
}

/** erfc(x) for x ≥ 3 by its continued fraction (modified Lentz), with no cancellation in the tail. */
function erfcContinuedFraction(x: number): number {
  const TINY = 1e-300;
  let f = x;
  let c = x;
  let d = 0;
  for (let n = 1; n <= 500; n += 1) {
    const a = n / 2;
    d = x + a * d;
    if (Math.abs(d) < TINY) d = TINY;
    d = 1 / d;
    c = x + a / c;
    if (Math.abs(c) < TINY) c = TINY;
    const delta = c * d;
    f *= delta;
    if (Math.abs(delta - 1) < 1e-16) break;
  }
  return Math.exp(-x * x) / (Math.sqrt(Math.PI) * f);
}

/** Upper tail of the standard normal, Q(z) = 1 − Φ(z), computed without subtracting from 1 in the tail. */
export function normalUpperTail(z: number): number {
  if (Number.isNaN(z)) return Number.NaN;
  const x = z / Math.SQRT2;
  if (x >= 3) return 0.5 * erfcContinuedFraction(x);
  if (x <= -3) return 1 - 0.5 * erfcContinuedFraction(-x);
  return 0.5 * (1 - erfSeries(x));
}

/** Standard normal distribution function Φ(z). */
export function normalCdf(z: number): number {
  return Number.isNaN(z) ? Number.NaN : normalUpperTail(-z);
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

function requireSamples(x: readonly number[], y: readonly number[], minimum: number) {
  if (x.length < minimum || y.length < minimum) throw new RangeError(`each sample needs at least ${minimum} values`);
  if (![...x, ...y].every(Number.isFinite)) throw new RangeError("samples must be finite numbers");
}

export type WelchResult = { t: number; degreesOfFreedom: number; p: number; meanDifference: number };

/** Welch's unequal-variances t-test on the means of x and y (two-sided). */
export function welchTTest(x: readonly number[], y: readonly number[]): WelchResult {
  requireSamples(x, y, 2);
  const stats = (values: readonly number[]) => {
    const n = values.length;
    const mean = values.reduce((sum, value) => sum + value, 0) / n;
    const variance = values.reduce((sum, value) => sum + (value - mean) ** 2, 0) / (n - 1);
    return { n, mean, variance };
  };
  const a = stats(x);
  const b = stats(y);
  const va = a.variance / a.n;
  const vb = b.variance / b.n;
  const meanDifference = a.mean - b.mean;
  if (va + vb === 0) {
    return { t: meanDifference === 0 ? 0 : Math.sign(meanDifference) * Infinity, degreesOfFreedom: a.n + b.n - 2, p: meanDifference === 0 ? 1 : 0, meanDifference };
  }
  const t = meanDifference / Math.sqrt(va + vb);
  const degreesOfFreedom = (va + vb) ** 2 / (va ** 2 / (a.n - 1) + vb ** 2 / (b.n - 1));
  return { t, degreesOfFreedom, p: studentTTwoSidedP(t, degreesOfFreedom), meanDifference };
}

export type CliffMagnitude = "negligible" | "small" | "medium" | "large";

export type MannWhitneyResult = {
  /** U for the first sample: the number of pairs with x > y, counting ties as one half. */
  u: number;
  z: number;
  p: number;
  /** Cliff's delta, P(X > Y) − P(X < Y), in [−1, 1]. Positive means x tends to be larger (slower). */
  cliffsDelta: number;
  magnitude: CliffMagnitude;
  /** Median of all pairwise differences x − y: the estimated shift, in the samples' unit. */
  hodgesLehmann: number;
};

export function cliffMagnitude(delta: number): CliffMagnitude {
  const size = Math.abs(delta);
  if (size < 0.147) return "negligible";
  if (size < 0.33) return "small";
  if (size < 0.474) return "medium";
  return "large";
}

/** Mann-Whitney U test (two-sided, normal approximation with tie and continuity corrections). */
export function mannWhitneyU(x: readonly number[], y: readonly number[]): MannWhitneyResult {
  requireSamples(x, y, 1);
  const n1 = x.length;
  const n2 = y.length;
  const n = n1 + n2;
  const pooled = [...x.map((value) => ({ value, group: 0 })), ...y.map((value) => ({ value, group: 1 }))].sort((a, b) => a.value - b.value);

  let rankSumX = 0;
  let tieTerm = 0;
  for (let start = 0; start < n; ) {
    let end = start;
    while (end + 1 < n && pooled[end + 1].value === pooled[start].value) end += 1;
    const averageRank = (start + end + 2) / 2;
    const tied = end - start + 1;
    if (tied > 1) tieTerm += tied ** 3 - tied;
    for (let index = start; index <= end; index += 1) if (pooled[index].group === 0) rankSumX += averageRank;
    start = end + 1;
  }

  const u = rankSumX - (n1 * (n1 + 1)) / 2;
  const meanU = (n1 * n2) / 2;
  const variance = n > 1 ? ((n1 * n2) / 12) * (n + 1 - tieTerm / (n * (n - 1))) : 0;
  let z = 0;
  let p = 1;
  if (variance > 0) {
    const distance = Math.max(0, Math.abs(u - meanU) - 0.5);
    z = (Math.sign(u - meanU) * distance) / Math.sqrt(variance);
    p = Math.min(1, 2 * normalUpperTail(Math.abs(z)));
  }

  const differences = new Float64Array(n1 * n2);
  let cursor = 0;
  for (const a of x) for (const b of y) differences[cursor++] = a - b;
  differences.sort();
  const middle = differences.length / 2;
  const hodgesLehmann = differences.length % 2 === 1 ? differences[Math.floor(middle)] : (differences[middle - 1] + differences[middle]) / 2;

  const cliffsDelta = (2 * u) / (n1 * n2) - 1;
  return { u, z, p, cliffsDelta, magnitude: cliffMagnitude(cliffsDelta), hodgesLehmann };
}

/** Holm-Bonferroni adjusted p-values, returned in the order the p-values were given. */
export function holmAdjust(pValues: readonly number[]): number[] {
  const m = pValues.length;
  const order = pValues.map((p, index) => ({ p, index })).sort((a, b) => a.p - b.p);
  const adjusted = new Array<number>(m);
  let running = 0;
  order.forEach(({ p, index }, rank) => {
    running = Math.max(running, Math.min(1, (m - rank) * p));
    adjusted[index] = running;
  });
  return adjusted;
}
