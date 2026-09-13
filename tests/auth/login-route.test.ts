import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { POST } from "@/app/api/auth/login/route";
import {
  LOGIN_MAX_FAILURES_PER_ACCOUNT,
  LOGIN_MAX_FAILURES_PER_CLIENT,
  loginRateLimit,
} from "@/lib/auth/rate-limit";
import { COOKIE_NAME, verifySessionToken } from "@/lib/auth/session";
import { prisma } from "@/lib/db";
import { DEMO_PASSWORD, seedUsers } from "@/prisma/fixtures";
import { resetDatabase } from "@/tests/helpers/db";

beforeAll(async () => {
  await resetDatabase();
  await seedUsers();
});

beforeEach(() => {
  loginRateLimit.clear();
});

function login(body: unknown, headers: Record<string, string> = {}) {
  return POST(
    new Request("http://localhost/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...headers },
      body: typeof body === "string" ? body : JSON.stringify(body),
    }),
  );
}

describe("POST /api/auth/login", () => {
  it("issues an httpOnly session cookie carrying the actor's role", async () => {
    const response = await login({ email: "signer@demo", password: DEMO_PASSWORD });
    expect(response.status).toBe(200);

    const cookie = response.cookies.get(COOKIE_NAME);
    expect(cookie?.httpOnly).toBe(true);
    expect(cookie?.sameSite).toBe("lax");
    expect(cookie?.path).toBe("/");

    const actor = await verifySessionToken(cookie!.value);
    expect(actor).toMatchObject({ email: "signer@demo", role: "SIGNER" });
  });

  it("accepts the demo account names from Section 5 Phase 9, which are not RFC emails", async () => {
    for (const email of ["admin@demo", "signer@demo", "verifier@demo", "viewer@demo"]) {
      expect((await login({ email, password: DEMO_PASSWORD })).status).toBe(200);
    }
  });

  it("rejects a wrong password with 401 and sets no cookie", async () => {
    const response = await login({ email: "signer@demo", password: "wrong" });
    expect(response.status).toBe(401);
    expect(response.cookies.get(COOKIE_NAME)).toBeUndefined();
  });

  it("gives the same message for an unknown account as for a wrong password", async () => {
    const unknown = await login({ email: "nobody@demo", password: DEMO_PASSWORD });
    const wrong = await login({ email: "signer@demo", password: "wrong" });
    expect(unknown.status).toBe(401);
    expect(await unknown.json()).toEqual(await wrong.json());
  });

  it("rejects malformed input with 400", async () => {
    expect((await login({ email: "signer@demo" })).status).toBe(400);
    expect((await login("not json")).status).toBe(400);
    expect((await login({ email: "x".repeat(300), password: "y" })).status).toBe(400);
  });
});

describe("failed-login throttling", () => {
  async function failRepeatedly(email: string, times: number, headers: Record<string, string> = {}) {
    for (let attempt = 0; attempt < times; attempt += 1) {
      expect((await login({ email, password: "wrong" }, headers)).status).toBe(401);
    }
  }

  it("locks an account after repeated failures, even against the correct password", async () => {
    await failRepeatedly("signer@demo", LOGIN_MAX_FAILURES_PER_ACCOUNT);

    const response = await login({ email: "signer@demo", password: DEMO_PASSWORD });
    expect(response.status).toBe(429);
    expect(Number(response.headers.get("Retry-After"))).toBeGreaterThan(0);
    expect(response.cookies.get(COOKIE_NAME)).toBeUndefined();

    const audit = await prisma.auditLogEntry.findFirst({
      where: { action: "USER_LOGIN_THROTTLED", targetId: "signer@demo" },
    });
    expect(audit).not.toBeNull();
    expect(audit!.metadataJson).not.toContain(DEMO_PASSWORD);
  });

  it("clears the failure count on a successful login", async () => {
    await failRepeatedly("signer@demo", LOGIN_MAX_FAILURES_PER_ACCOUNT - 1);
    expect((await login({ email: "signer@demo", password: DEMO_PASSWORD })).status).toBe(200);
    await failRepeatedly("signer@demo", LOGIN_MAX_FAILURES_PER_ACCOUNT - 1);
    expect((await login({ email: "signer@demo", password: DEMO_PASSWORD })).status).toBe(200);
  });

  it("locks per account, leaving other accounts unaffected", async () => {
    await failRepeatedly("signer@demo", LOGIN_MAX_FAILURES_PER_ACCOUNT);
    expect((await login({ email: "admin@demo", password: DEMO_PASSWORD })).status).toBe(200);
  });

  it("cannot be sidestepped by changing the case of the account name", async () => {
    const variants = ["signer@demo", "SIGNER@demo", "Signer@Demo", "signer@DEMO", "sIgNeR@demo"];
    for (const email of variants) {
      expect((await login({ email, password: "wrong" })).status).toBe(401);
    }
    expect((await login({ email: "signer@demo", password: DEMO_PASSWORD })).status).toBe(429);
  });

  it("also limits one forwarded client spraying guesses across many accounts", async () => {
    const attacker = { "x-forwarded-for": "203.0.113.50" };
    const accounts = Math.ceil(LOGIN_MAX_FAILURES_PER_CLIENT / (LOGIN_MAX_FAILURES_PER_ACCOUNT - 1));
    let failures = 0;
    for (let index = 0; index < accounts && failures < LOGIN_MAX_FAILURES_PER_CLIENT; index += 1) {
      const perAccount = Math.min(
        LOGIN_MAX_FAILURES_PER_ACCOUNT - 1,
        LOGIN_MAX_FAILURES_PER_CLIENT - failures,
      );
      await failRepeatedly(`spray-${index}@demo`, perAccount, attacker);
      failures += perAccount;
    }

    expect((await login({ email: "viewer@demo", password: DEMO_PASSWORD }, attacker)).status).toBe(
      429,
    );
    // A different client is not caught by that limit.
    expect(
      (
        await login(
          { email: "viewer@demo", password: DEMO_PASSWORD },
          { "x-forwarded-for": "198.51.100.9" },
        )
      ).status,
    ).toBe(200);
  }, 60_000);
});
