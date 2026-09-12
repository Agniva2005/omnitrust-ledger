import { beforeAll, describe, expect, it } from "vitest";
import { prisma } from "@/lib/db";
import {
  authenticate,
  createSessionToken,
  hashPassword,
  verifyPassword,
  verifySessionToken,
} from "@/lib/auth/session";
import { DEMO_PASSWORD, seedUsers } from "@/prisma/fixtures";
import { resetDatabase } from "@/tests/helpers/db";

beforeAll(async () => {
  await resetDatabase();
  await seedUsers();
});

describe("password hashing", () => {
  it("verifies a correct password and rejects a wrong one", async () => {
    const hash = await hashPassword("correct horse battery staple");
    expect(await verifyPassword("correct horse battery staple", hash)).toBe(true);
    expect(await verifyPassword("Correct horse battery staple", hash)).toBe(false);
  });

  it("stores a bcrypt hash, never the plaintext", async () => {
    const hash = await hashPassword(DEMO_PASSWORD);
    expect(hash).toMatch(/^\$2[aby]\$12\$/);
    expect(hash).not.toContain(DEMO_PASSWORD);
  });

  it("salts, so the same password hashes differently each time", async () => {
    expect(await hashPassword("same")).not.toBe(await hashPassword("same"));
  });
});

describe("authenticate", () => {
  it("accepts a seeded user with the right password", async () => {
    const actor = await authenticate("signer@demo", DEMO_PASSWORD);
    expect(actor).not.toBeNull();
    expect(actor?.role).toBe("SIGNER");
  });

  it("resolves every seeded demo account to its expected role", async () => {
    for (const [email, role] of [
      ["admin@demo", "ADMIN"],
      ["signer@demo", "SIGNER"],
      ["verifier@demo", "VERIFIER"],
      ["viewer@demo", "VIEWER"],
    ]) {
      expect((await authenticate(email, DEMO_PASSWORD))?.role).toBe(role);
    }
  });

  it("rejects a wrong password", async () => {
    expect(await authenticate("signer@demo", "wrong-password")).toBeNull();
  });

  it("rejects an unknown account without distinguishing it from a wrong password", async () => {
    expect(await authenticate("nobody@demo", DEMO_PASSWORD)).toBeNull();
  });
});

describe("session tokens", () => {
  const actor = { userId: "user-1", email: "signer@demo", role: "SIGNER" as const };

  it("round-trips an actor", async () => {
    const token = await createSessionToken(actor);
    expect(await verifySessionToken(token)).toEqual(actor);
  });

  it("rejects a token whose payload has been tampered with", async () => {
    const token = await createSessionToken(actor);
    const [header, payload, signature] = token.split(".");
    const decoded = JSON.parse(Buffer.from(payload, "base64url").toString());
    decoded.role = "ADMIN";
    const forged = [
      header,
      Buffer.from(JSON.stringify(decoded)).toString("base64url"),
      signature,
    ].join(".");

    expect(await verifySessionToken(forged)).toBeNull();
  });

  it("rejects a token signed with a different secret", async () => {
    const original = process.env.JWT_SECRET;
    process.env.JWT_SECRET = "a-completely-different-secret-key-32ch";
    const foreign = await createSessionToken({ ...actor, role: "ADMIN" });
    process.env.JWT_SECRET = original;

    expect(await verifySessionToken(foreign)).toBeNull();
  });

  it("rejects garbage", async () => {
    for (const junk of ["", "not-a-token", "a.b.c"]) {
      expect(await verifySessionToken(junk)).toBeNull();
    }
  });
});
