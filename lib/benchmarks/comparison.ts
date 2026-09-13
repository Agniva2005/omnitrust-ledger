// Pairwise comparison of timing samples between algorithms, for one operation at a time.
//
// For every unordered pair (in the order the groups are given) it reports the medians and their
// ratio, the Hodges-Lehmann shift, Cliff's delta, and two-sided Mann-Whitney and Welch p-values,
// each adjusted with Holm's method across all pairs of the same operation. The Mann-Whitney result
// after adjustment is the primary significance call: timing samples are skewed, and the question
// asked is whether one algorithm's timings are shifted relative to another's.
import { holmAdjust, mannWhitneyU, welchTTest, type CliffMagnitude } from "@/lib/benchmarks/inference";
import { median } from "@/lib/benchmarks/statistics";

export type PairwiseComparison = {
  a: string;
  b: string;
  medianA: number;
  medianB: number;
  /** medianA / medianB. */
  ratioOfMedians: number;
  /** Median of all pairwise differences a − b, in the samples' unit. */
  hodgesLehmann: number;
  cliffsDelta: number;
  magnitude: CliffMagnitude;
  mannWhitneyP: number;
  mannWhitneyPHolm: number;
  welchP: number;
  welchPHolm: number;
  /** Mann-Whitney, Holm-adjusted across this operation's pairs, below 0.05. */
  significantAt05: boolean;
};

export const SIGNIFICANCE_LEVEL = 0.05;

export function pairwiseComparisons(groups: Record<string, readonly number[]>): PairwiseComparison[] {
  const names = Object.keys(groups);
  const raw: Omit<PairwiseComparison, "mannWhitneyPHolm" | "welchPHolm" | "significantAt05">[] = [];
  for (let i = 0; i < names.length; i += 1) {
    for (let j = i + 1; j < names.length; j += 1) {
      const a = groups[names[i]];
      const b = groups[names[j]];
      const mw = mannWhitneyU(a, b);
      const welch = welchTTest(a, b);
      const medianA = median(a);
      const medianB = median(b);
      raw.push({
        a: names[i],
        b: names[j],
        medianA,
        medianB,
        ratioOfMedians: medianB === 0 ? Number.POSITIVE_INFINITY : medianA / medianB,
        hodgesLehmann: mw.hodgesLehmann,
        cliffsDelta: mw.cliffsDelta,
        magnitude: mw.magnitude,
        mannWhitneyP: mw.p,
        welchP: welch.p,
      });
    }
  }
  const mannWhitneyHolm = holmAdjust(raw.map((row) => row.mannWhitneyP));
  const welchHolm = holmAdjust(raw.map((row) => row.welchP));
  return raw.map((row, index) => ({
    ...row,
    mannWhitneyPHolm: mannWhitneyHolm[index],
    welchPHolm: welchHolm[index],
    significantAt05: mannWhitneyHolm[index] < SIGNIFICANCE_LEVEL,
  }));
}
