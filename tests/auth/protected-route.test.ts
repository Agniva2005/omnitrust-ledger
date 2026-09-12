import { beforeEach, describe, expect, it, vi } from "vitest";
import { COOKIE_NAME, createSessionToken } from "@/lib/auth/session";
import type { Role } from "@/lib/auth/rbac";

// The route handler reads its session from the request cookie via next/headers,
// which only exists inside a request scope. Everything else in the handler --
// token verification, requireRole, status mapping -- is the real implementation.
const state = vi.hoisted(() => ({ token: null as string | null }));

vi.mock("next/headers", () => ({
  cookies: async () => ({
    get: (name: string) =>
      name === COOKIE_NAME && state.token ? { name, value: state.token } : undefined,
  }),
}));

const { GET } = await import("@/app/api/admin/probe/route");

async function probeAs(role: Role | null) {
  state.token = role
    ? await createSessionToken({ userId: `user-${role}`, email: `${role}@demo`, role })
    : null;
  return GET();
}

beforeEach(() => {
  state.token = null;
});

describe("ADMIN-only route", () => {
  it("allows an ADMIN", async () => {
    const response = await probeAs("ADMIN");
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({ ok: true, role: "ADMIN" });
  });

  it.each(["SIGNER", "VERIFIER", "VIEWER"] as const)("rejects a %s with 403", async (role) => {
    const response = await probeAs(role);
    expect(response.status).toBe(403);
    expect((await response.json()).error).toContain(role);
  });

  it("rejects an unauthenticated request with 401", async () => {
    expect((await probeAs(null)).status).toBe(401);
  });

  it("rejects a forged cookie value with 401", async () => {
    state.token = "not.a.real.token";
    expect((await GET()).status).toBe(401);
  });
});
