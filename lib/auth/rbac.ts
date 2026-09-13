import { HttpError } from "@/lib/errors";

export const ROLES = ["ADMIN", "SIGNER", "VERIFIER", "VIEWER"] as const;

export type Role = (typeof ROLES)[number];

export function isRole(value: unknown): value is Role {
  return typeof value === "string" && (ROLES as readonly string[]).includes(value);
}

export function assertRole(value: unknown): Role {
  if (!isRole(value)) throw new Error(`Unknown role: ${String(value)}`);
  return value;
}

export type Capability =
  | "document:read"
  | "document:upload"
  | "document:sign"
  | "document:verify"
  | "certificate:read"
  | "certificate:issue"
  | "certificate:revoke"
  | "audit:read"
  | "audit:verify";

const CAPABILITIES: Record<Capability, readonly Role[]> = {
  "document:read": ROLES,
  "document:upload": ["ADMIN", "SIGNER"],
  "document:sign": ["ADMIN", "SIGNER"],
  "document:verify": ["ADMIN", "SIGNER", "VERIFIER"],
  "certificate:read": ROLES,
  "certificate:issue": ["ADMIN", "SIGNER"],
  "certificate:revoke": ["ADMIN"],
  "audit:read": ROLES,
  "audit:verify": ["ADMIN", "VERIFIER"],
};

export type Actor = { userId: string; email: string; role: Role };

export class AuthenticationError extends HttpError {
  readonly status = 401;
  constructor(message = "Authentication required") {
    super(message);
    this.name = "AuthenticationError";
  }
}

export class AuthorizationError extends HttpError {
  readonly status = 403;
  constructor(message = "Insufficient permissions") {
    super(message);
    this.name = "AuthorizationError";
  }
}

export function can(role: Role, capability: Capability): boolean {
  return CAPABILITIES[capability].includes(role);
}

export function capabilitiesFor(role: Role): Capability[] {
  return (Object.keys(CAPABILITIES) as Capability[]).filter((capability) =>
    can(role, capability),
  );
}

export function requireRole(actor: Actor | null, allowed: readonly Role[]): Actor {
  if (!actor) throw new AuthenticationError();
  if (!allowed.includes(actor.role)) {
    throw new AuthorizationError(
      `Role ${actor.role} is not one of: ${allowed.join(", ")}`,
    );
  }
  return actor;
}

export function requireCapability(actor: Actor | null, capability: Capability): Actor {
  if (!actor) throw new AuthenticationError();
  if (!can(actor.role, capability)) {
    throw new AuthorizationError(`Role ${actor.role} cannot perform ${capability}`);
  }
  return actor;
}
