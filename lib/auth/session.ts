import bcrypt from "bcryptjs";
import { SignJWT, jwtVerify } from "jose";
import { prisma } from "@/lib/db";
import { isRole, type Actor } from "@/lib/auth/rbac";

const COOKIE_NAME = "omnitrust_session";
const SESSION_TTL_SECONDS = 8 * 60 * 60;
const BCRYPT_ROUNDS = 12;
const ISSUER = "omnitrust-ledger";

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
    .setIssuer(ISSUER)
    .setExpirationTime(`${SESSION_TTL_SECONDS}s`)
    .sign(secret());
}

/**
 * Checks the token's signature, issuer and expiry and returns its claims. The algorithm
 * is pinned so a token cannot select its own verification method.
 */
export async function verifySessionToken(token: string): Promise<Actor | null> {
  try {
    const { payload } = await jwtVerify(token, secret(), {
      issuer: ISSUER,
      algorithms: ["HS256"],
    });
    if (!payload.sub || typeof payload.email !== "string" || !isRole(payload.role)) return null;
    return { userId: payload.sub, email: payload.email, role: payload.role };
  } catch {
    return null;
  }
}

/**
 * Resolves a token to the user as the database describes them now. The token proves who
 * authenticated; the role is read from the user row, so deleting or demoting a user
 * takes effect on their next request rather than when the token expires.
 */
export async function actorFromSessionToken(token: string): Promise<Actor | null> {
  const claims = await verifySessionToken(token);
  if (!claims) return null;

  const user = await prisma.user.findUnique({
    where: { id: claims.userId },
    select: { id: true, email: true, role: true },
  });
  if (!user || !isRole(user.role)) return null;
  return { userId: user.id, email: user.email, role: user.role };
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
  if (!isRole(user.role)) return null;
  return { userId: user.id, email: user.email, role: user.role };
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
  return actorFromSessionToken(token);
}
