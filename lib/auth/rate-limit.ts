// Failed-login throttling. In-memory and per process: adequate for this single-process
// demonstrator, and stated as such in the README limitations.

type Window = { count: number; resetAt: number };

const PRUNE_THRESHOLD = 10_000;

/** Counts failures per key inside a fixed window and blocks the key once the limit is hit. */
export class FailureRateLimiter {
  private readonly windows = new Map<string, Window>();

  constructor(
    private readonly limit: number,
    private readonly windowMs: number,
    private readonly now: () => number = Date.now,
  ) {}

  /** Seconds until the key may try again, or 0 when it is not blocked. */
  retryAfterSeconds(key: string): number {
    const window = this.current(key);
    if (!window || window.count < this.limit) return 0;
    return Math.max(1, Math.ceil((window.resetAt - this.now()) / 1000));
  }

  recordFailure(key: string): void {
    const window = this.current(key);
    if (window) {
      window.count += 1;
      return;
    }
    if (this.windows.size >= PRUNE_THRESHOLD) this.prune();
    this.windows.set(key, { count: 1, resetAt: this.now() + this.windowMs });
  }

  reset(key: string): void {
    this.windows.delete(key);
  }

  clear(): void {
    this.windows.clear();
  }

  private current(key: string): Window | undefined {
    const window = this.windows.get(key);
    if (window && window.resetAt <= this.now()) {
      this.windows.delete(key);
      return undefined;
    }
    return window;
  }

  private prune(): void {
    const now = this.now();
    for (const [key, window] of this.windows) {
      if (window.resetAt <= now) this.windows.delete(key);
    }
  }
}

export const LOGIN_WINDOW_MS = 15 * 60 * 1000;
export const LOGIN_MAX_FAILURES_PER_ACCOUNT = 5;
export const LOGIN_MAX_FAILURES_PER_CLIENT = 20;

const accountLimiter = new FailureRateLimiter(LOGIN_MAX_FAILURES_PER_ACCOUNT, LOGIN_WINDOW_MS);
const clientLimiter = new FailureRateLimiter(LOGIN_MAX_FAILURES_PER_CLIENT, LOGIN_WINDOW_MS);

/**
 * The forwarding header is only trustworthy behind a proxy that sets it, and anyone can
 * forge it otherwise. The per-client limit is therefore a secondary control; the
 * per-account limit is the one that cannot be sidestepped. Without the header there is
 * no per-client key at all, so one caller cannot lock every direct client out.
 */
export function clientKey(request: Request): string | null {
  return request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || null;
}

export function accountKey(identifier: string): string {
  return identifier.toLowerCase().trim();
}

export const loginRateLimit = {
  retryAfterSeconds(account: string, client: string | null): number {
    return Math.max(
      accountLimiter.retryAfterSeconds(account),
      client ? clientLimiter.retryAfterSeconds(client) : 0,
    );
  },

  recordFailure(account: string, client: string | null): void {
    accountLimiter.recordFailure(account);
    if (client) clientLimiter.recordFailure(client);
  },

  recordSuccess(account: string): void {
    accountLimiter.reset(account);
  },

  clear(): void {
    accountLimiter.clear();
    clientLimiter.clear();
  },
};
