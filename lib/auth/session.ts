import bcrypt from "bcryptjs";
import { SignJWT, jwtVerify } from "jose";
import { prisma } from "@/lib/db";
import { assertRole, type Actor } from "@/lib/auth/rbac";

const COOKIE_NAME = "omnitrust_session";
const SESSION_TTL_SECONDS = 8 * 60 * 60;
const BCRYPT_ROUNDS = 12;

export { COOKIE_NAME, SESSION_TTL_SECONDS };

function secret(): Uint8Array {
  const value = process.env.JWT_SECRET;
  if (!value || value.length < 32) {
    throw new Error(
      "JWT_SECRET is missing or too short (need >= 32 chars). Run `npm run setup`.",
    );
  }
  return new TextEncoder().encode(value);
}

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, BCRYPT_ROUNDS);
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

export async function createSessionToken(actor: Actor): Promise<string> {
  return new SignJWT({ email: actor.email, role: actor.role })
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(actor.userId)
    .setIssuedAt()
    .setIssuer("omnitrust-ledger")
    .setExpirationTime(`${SESSION_TTL_SECONDS}s`)
    .sign(secret());
}

export async function verifySessionToken(token: string): Promise<Actor | null> {
  try {
    const { payload } = await jwtVerify(token, secret(), { issuer: "omnitrust-ledger" });
    if (!payload.sub || typeof payload.email !== "string") return null;
    return { userId: payload.sub, email: payload.email, role: assertRole(payload.role) };
  } catch {
    return null;
  }
}

let decoy: Promise<string> | null = null;

function decoyHash(): Promise<string> {
  decoy ??= bcrypt.hash("omnitrust-decoy", BCRYPT_ROUNDS);
  return decoy;
}

/**
 * Credential check. Returns null for both "no such user" and "wrong password" so
 * callers cannot use the outcome to enumerate accounts.
 */
export async function authenticate(email: string, password: string): Promise<Actor | null> {
  const user = await prisma.user.findUnique({ where: { email: email.toLowerCase().trim() } });
  if (!user) {
    // Equalises response time between a missing account and a wrong password.
    await bcrypt.compare(password, await decoyHash());
    return null;
  }
  if (!(await verifyPassword(password, user.passwordHash))) return null;
  return { userId: user.id, email: user.email, role: assertRole(user.role) };
}

export function sessionCookie(token: string) {
  return {
    name: COOKIE_NAME,
    value: token,
    httpOnly: true,
    sameSite: "lax" as const,
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: SESSION_TTL_SECONDS,
  };
}

export function clearedSessionCookie() {
  return { ...sessionCookie(""), maxAge: 0 };
}

/** Current actor from the request cookie, or null. Server-side only. */
export async function getSession(): Promise<Actor | null> {
  const { cookies } = await import("next/headers");
  const token = (await cookies()).get(COOKIE_NAME)?.value;
  if (!token) return null;
  return verifySessionToken(token);
}
