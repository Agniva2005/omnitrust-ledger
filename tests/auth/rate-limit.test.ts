import { describe, expect, it } from "vitest";
import { FailureRateLimiter, accountKey, clientKey } from "@/lib/auth/rate-limit";

function limiterWithClock(limit: number, windowMs: number) {
  const clock = { now: 1_000_000 };
  return { clock, limiter: new FailureRateLimiter(limit, windowMs, () => clock.now) };
}

describe("FailureRateLimiter", () => {
  it("allows attempts until the limit, then blocks with a retry-after", () => {
    const { limiter } = limiterWithClock(3, 60_000);
    for (let attempt = 0; attempt < 3; attempt += 1) {
      expect(limiter.retryAfterSeconds("key")).toBe(0);
      limiter.recordFailure("key");
    }
    expect(limiter.retryAfterSeconds("key")).toBe(60);
  });

  it("unblocks once the window has passed", () => {
    const { clock, limiter } = limiterWithClock(2, 10_000);
    limiter.recordFailure("key");
    limiter.recordFailure("key");
    expect(limiter.retryAfterSeconds("key")).toBeGreaterThan(0);

    clock.now += 10_000;
    expect(limiter.retryAfterSeconds("key")).toBe(0);
  });

  it("counts down the retry-after as the window runs out", () => {
    const { clock, limiter } = limiterWithClock(1, 30_000);
    limiter.recordFailure("key");
    clock.now += 20_500;
    expect(limiter.retryAfterSeconds("key")).toBe(10);
  });

  it("keeps keys independent", () => {
    const { limiter } = limiterWithClock(1, 60_000);
    limiter.recordFailure("a");
    expect(limiter.retryAfterSeconds("a")).toBeGreaterThan(0);
    expect(limiter.retryAfterSeconds("b")).toBe(0);
  });

  it("clears a key on reset", () => {
    const { limiter } = limiterWithClock(1, 60_000);
    limiter.recordFailure("key");
    limiter.reset("key");
    expect(limiter.retryAfterSeconds("key")).toBe(0);
  });
});

describe("keys", () => {
  it("normalises account identifiers so case cannot sidestep the limit", () => {
    expect(accountKey("  Signer@DEMO ")).toBe(accountKey("signer@demo"));
  });

  it("uses the first forwarded address, and no client key without the header", () => {
    const forwarded = new Request("http://localhost/", {
      headers: { "x-forwarded-for": "203.0.113.7, 10.0.0.1" },
    });
    expect(clientKey(forwarded)).toBe("203.0.113.7");
    expect(clientKey(new Request("http://localhost/"))).toBeNull();
  });
});
