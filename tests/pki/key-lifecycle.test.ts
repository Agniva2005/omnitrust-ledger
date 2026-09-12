import { describe, expect, it } from "vitest";
import {
  CERTIFICATE_STATES,
  InvalidKeyTransitionError,
  KEY_STATES,
  assertCertificateTransition,
  assertKeyTransition,
  canTransitionCertificate,
  canTransitionKey,
  nextCertificateStates,
  nextKeyStates,
  type CertificateState,
  type KeyState,
} from "@/lib/pki/keys";

describe("key lifecycle, Figure 7 / NIST SP 800-57", () => {
  it("walks generated -> active -> rotated -> revoked -> retired", () => {
    const path: KeyState[] = ["GENERATED", "ACTIVE", "ROTATED", "REVOKED", "RETIRED"];
    for (let index = 1; index < path.length; index += 1) {
      expect(canTransitionKey(path[index - 1], path[index])).toBe(true);
    }
  });

  it("allows an active key to be revoked without rotating first", () => {
    expect(canTransitionKey("ACTIVE", "REVOKED")).toBe(true);
  });

  it("does not allow a revoked key to become active again", () => {
    expect(canTransitionKey("REVOKED", "ACTIVE")).toBe(false);
    expect(() => assertKeyTransition("REVOKED", "ACTIVE")).toThrow(InvalidKeyTransitionError);
  });

  it("treats RETIRED as terminal", () => {
    expect(nextKeyStates("RETIRED")).toHaveLength(0);
    for (const state of KEY_STATES) expect(canTransitionKey("RETIRED", state)).toBe(false);
  });

  it("never returns to GENERATED", () => {
    for (const state of KEY_STATES) {
      expect(canTransitionKey(state, "GENERATED")).toBe(false);
    }
  });
});

describe("certificate lifecycle, Figure 6", () => {
  it("walks requested -> active -> expired", () => {
    expect(canTransitionCertificate("REQUESTED", "ACTIVE")).toBe(true);
    expect(canTransitionCertificate("ACTIVE", "EXPIRED")).toBe(true);
  });

  it("allows an active or expired certificate to be revoked", () => {
    expect(canTransitionCertificate("ACTIVE", "REVOKED")).toBe(true);
    expect(canTransitionCertificate("EXPIRED", "REVOKED")).toBe(true);
  });

  it("treats REVOKED as terminal, so nothing un-revokes", () => {
    expect(nextCertificateStates("REVOKED")).toHaveLength(0);
    for (const state of CERTIFICATE_STATES) {
      expect(canTransitionCertificate("REVOKED", state)).toBe(false);
    }
  });

  it("does not allow an expired certificate to become active again", () => {
    expect(() => assertCertificateTransition("EXPIRED", "ACTIVE")).toThrow(
      /EXPIRED -> ACTIVE/,
    );
  });

  it("declares a transition list for every state, with only declared targets", () => {
    for (const state of CERTIFICATE_STATES) {
      for (const target of nextCertificateStates(state as CertificateState)) {
        expect(CERTIFICATE_STATES).toContain(target);
      }
    }
  });
});
