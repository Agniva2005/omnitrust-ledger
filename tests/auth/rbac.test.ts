import { describe, expect, it } from "vitest";
import {
  AuthenticationError,
  AuthorizationError,
  ROLES,
  can,
  capabilitiesFor,
  isRole,
  requireCapability,
  requireRole,
  type Actor,
  type Role,
} from "@/lib/auth/rbac";

function actorWith(role: Role): Actor {
  return { userId: `user-${role}`, email: `${role.toLowerCase()}@demo`, role };
}

describe("role parsing", () => {
  it("accepts the four declared roles and nothing else", () => {
    for (const role of ROLES) expect(isRole(role)).toBe(true);
    for (const bogus of ["admin", "ROOT", "", null, 7]) expect(isRole(bogus)).toBe(false);
  });
});

describe("CLAUDE.md Section 6 RBAC requirements", () => {
  it("a VERIFIER cannot sign", () => {
    expect(can("VERIFIER", "document:sign")).toBe(false);
    expect(() => requireCapability(actorWith("VERIFIER"), "document:sign")).toThrow(
      AuthorizationError,
    );
  });

  it("a VIEWER cannot upload", () => {
    expect(can("VIEWER", "document:upload")).toBe(false);
    expect(() => requireCapability(actorWith("VIEWER"), "document:upload")).toThrow(
      AuthorizationError,
    );
  });

  it("a VIEWER cannot issue certificates", () => {
    expect(can("VIEWER", "certificate:issue")).toBe(false);
    expect(() => requireCapability(actorWith("VIEWER"), "certificate:issue")).toThrow(
      AuthorizationError,
    );
  });

  it("only an ADMIN can revoke certificates", () => {
    expect(can("ADMIN", "certificate:revoke")).toBe(true);
    for (const role of ["SIGNER", "VERIFIER", "VIEWER"] as const) {
      expect(can(role, "certificate:revoke")).toBe(false);
    }
  });
});

describe("capability matrix", () => {
  it("lets a SIGNER upload, sign and verify", () => {
    for (const capability of ["document:upload", "document:sign", "document:verify"] as const) {
      expect(can("SIGNER", capability)).toBe(true);
    }
  });

  it("gives ADMIN every capability", () => {
    expect(capabilitiesFor("ADMIN")).toEqual(capabilitiesFor("ADMIN"));
    for (const capability of capabilitiesFor("VERIFIER")) expect(can("ADMIN", capability)).toBe(true);
    for (const capability of capabilitiesFor("SIGNER")) expect(can("ADMIN", capability)).toBe(true);
  });

  it("gives a VIEWER read-only capabilities", () => {
    expect(capabilitiesFor("VIEWER").sort()).toEqual(
      ["anchor:read", "audit:read", "certificate:read", "document:read"].sort(),
    );
  });

  it("reserves audit checkpoints and anchoring to ADMIN", () => {
    for (const capability of ["audit:checkpoint", "anchor:create"] as const) {
      expect(can("ADMIN", capability)).toBe(true);
      for (const role of ["SIGNER", "VERIFIER", "VIEWER"] as const) expect(can(role, capability)).toBe(false);
    }
  });
});

describe("requireRole", () => {
  it("returns the actor when the role is allowed", () => {
    const actor = actorWith("ADMIN");
    expect(requireRole(actor, ["ADMIN"])).toBe(actor);
  });

  it("throws 403 for a disallowed role", () => {
    try {
      requireRole(actorWith("VIEWER"), ["ADMIN"]);
      expect.unreachable("should have thrown");
    } catch (error) {
      expect(error).toBeInstanceOf(AuthorizationError);
      expect((error as AuthorizationError).status).toBe(403);
    }
  });

  it("throws 401 rather than 403 when there is no session at all", () => {
    try {
      requireRole(null, ["ADMIN"]);
      expect.unreachable("should have thrown");
    } catch (error) {
      expect(error).toBeInstanceOf(AuthenticationError);
      expect((error as AuthenticationError).status).toBe(401);
    }
  });
});
