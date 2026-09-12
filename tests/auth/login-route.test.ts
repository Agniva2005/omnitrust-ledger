import { beforeAll, describe, expect, it } from "vitest";
import { POST } from "@/app/api/auth/login/route";
import { COOKIE_NAME, verifySessionToken } from "@/lib/auth/session";
import { prisma } from "@/lib/db";
import { DEMO_PASSWORD, seedUsers } from "@/prisma/fixtures";

beforeAll(async () => {
  await prisma.user.deleteMany();
  await seedUsers();
});

function login(body: unknown) {
  return POST(
    new Request("http://localhost/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
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
