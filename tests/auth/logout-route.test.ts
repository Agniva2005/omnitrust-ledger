import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { COOKIE_NAME, createSessionToken } from "@/lib/auth/session";
import { prisma } from "@/lib/db";
import { seedUsers } from "@/prisma/fixtures";
import { resetDatabase } from "@/tests/helpers/db";

const state = vi.hoisted(() => ({ token: null as string | null }));

vi.mock("next/headers", () => ({
  cookies: async () => ({
    get: (name: string) =>
      name === COOKIE_NAME && state.token ? { name, value: state.token } : undefined,
  }),
}));

const { POST } = await import("@/app/api/auth/logout/route");

beforeAll(async () => {
  await resetDatabase();
  await seedUsers();
});

beforeEach(async () => {
  state.token = null;
  await prisma.auditLogEntry.deleteMany();
});

describe("POST /api/auth/logout", () => {
  it("clears the session cookie and records USER_LOGOUT for the signed-in user", async () => {
    const user = await prisma.user.findUniqueOrThrow({ where: { email: "signer@demo" } });
    state.token = await createSessionToken({ userId: user.id, email: user.email, role: "SIGNER" });

    const response = await POST();

    expect(response.status).toBe(200);
    const cookie = response.cookies.get(COOKIE_NAME);
    expect(cookie?.value).toBe("");
    expect(cookie?.maxAge).toBe(0);

    const entry = await prisma.auditLogEntry.findFirstOrThrow({ where: { action: "USER_LOGOUT" } });
    expect(entry.actorUserId).toBe(user.id);
  });

  it("still clears the cookie without a session, and records nothing", async () => {
    const response = await POST();
    expect(response.cookies.get(COOKIE_NAME)?.maxAge).toBe(0);
    expect(await prisma.auditLogEntry.count({ where: { action: "USER_LOGOUT" } })).toBe(0);
  });
});
