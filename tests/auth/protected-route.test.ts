import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { COOKIE_NAME, createSessionToken } from "@/lib/auth/session";
import type { Role } from "@/lib/auth/rbac";
import { prisma } from "@/lib/db";
import { seedUsers } from "@/prisma/fixtures";
import { resetDatabase } from "@/tests/helpers/db";

// The route handler reads its session from the request cookie via next/headers,
// which only exists inside a request scope. Everything else in the handler --
// token verification, the user lookup, requireRole, status mapping -- is real.
const state = vi.hoisted(() => ({ token: null as string | null }));

vi.mock("next/headers", () => ({
  cookies: async () => ({
    get: (name: string) =>
      name === COOKIE_NAME && state.token ? { name, value: state.token } : undefined,
  }),
}));

const { GET } = await import("@/app/api/admin/probe/route");

beforeAll(async () => {
  await resetDatabase();
  await seedUsers();
});

beforeEach(() => {
  state.token = null;
});

async function tokenFor(email: string) {
  const user = await prisma.user.findUniqueOrThrow({ where: { email } });
  return createSessionToken({ userId: user.id, email: user.email, role: user.role as Role });
}

describe("ADMIN-only route", () => {
  it("allows an ADMIN", async () => {
    state.token = await tokenFor("admin@demo");
    const response = await GET();
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({ ok: true, role: "ADMIN" });
  });

  it.each(["signer@demo", "verifier@demo", "viewer@demo"])("rejects %s with 403", async (email) => {
    state.token = await tokenFor(email);
    const response = await GET();
    expect(response.status).toBe(403);
  });

  it("rejects an unauthenticated request with 401", async () => {
    expect((await GET()).status).toBe(401);
  });

  it("rejects a forged cookie value with 401", async () => {
    state.token = "not.a.real.token";
    expect((await GET()).status).toBe(401);
  });
});

describe("the session is re-checked against the database on every request", () => {
  it("rejects a validly signed token for a user that does not exist", async () => {
    state.token = await createSessionToken({
      userId: "no-such-user",
      email: "ghost@demo",
      role: "ADMIN",
    });
    expect((await GET()).status).toBe(401);
  });

  it("applies the user's current role, not the role frozen into the token", async () => {
    state.token = await tokenFor("admin@demo");
    expect((await GET()).status).toBe(200);

    await prisma.user.update({ where: { email: "admin@demo" }, data: { role: "VIEWER" } });
    try {
      // Same token, still unexpired and correctly signed: the demotion wins.
      expect((await GET()).status).toBe(403);
    } finally {
      await prisma.user.update({ where: { email: "admin@demo" }, data: { role: "ADMIN" } });
    }
  });
});
