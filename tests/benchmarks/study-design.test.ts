// The migration study orders its measurements with a seeded generator so that drift and warm-up are
// spread across algorithms and a run's order can be reproduced. These tests check that ordering is
// deterministic per seed and that a shuffle is always a permutation.
import { describe, expect, it } from "vitest";
import { seededRandom, shuffled } from "@/scripts/migration-study";

describe("seededRandom", () => {
  it("repeats its sequence for the same seed and diverges for another", () => {
    const a = seededRandom(20260914);
    const b = seededRandom(20260914);
    const c = seededRandom(20260915);
    const first = Array.from({ length: 8 }, () => a());
    expect(Array.from({ length: 8 }, () => b())).toEqual(first);
    expect(Array.from({ length: 8 }, () => c())).not.toEqual(first);
  });

  it("stays in [0, 1) and spreads over the interval", () => {
    const random = seededRandom(7);
    const values = Array.from({ length: 10_000 }, () => random());
    expect(values.every((value) => value >= 0 && value < 1)).toBe(true);
    const buckets = new Array(10).fill(0);
    for (const value of values) buckets[Math.floor(value * 10)] += 1;
    // Each decile should hold roughly a tenth of the draws.
    for (const count of buckets) expect(count).toBeGreaterThan(850);
  });
});

describe("shuffled", () => {
  const items = ["a", "b", "c", "d", "e"];

  it("returns a permutation and leaves the input untouched", () => {
    const random = seededRandom(1);
    for (let round = 0; round < 50; round += 1) {
      const result = shuffled(items, random);
      expect([...result].sort()).toEqual(items);
    }
    expect(items).toEqual(["a", "b", "c", "d", "e"]);
  });

  it("puts every item first in some rounds, so no algorithm always runs first", () => {
    const random = seededRandom(20260914);
    const firsts = new Set(Array.from({ length: 200 }, () => shuffled(items, random)[0]));
    expect([...firsts].sort()).toEqual(items);
  });
});
