import { describe, expect, it } from "vitest";
import {
  DOCUMENT_STATES,
  InvalidTransitionError,
  assertPath,
  assertTransition,
  canTransition,
  isTerminal,
  nextStates,
  type DocumentState,
} from "@/lib/documents/lifecycle";

describe("Figure 4 happy path", () => {
  it("walks created -> uploaded -> hashed -> signed -> stored -> verified -> versioned", () => {
    expect(
      assertPath([
        "CREATED",
        "UPLOADED",
        "HASHED",
        "SIGNED",
        "STORED",
        "VERIFIED",
        "VERSIONED",
      ]),
    ).toBe("VERSIONED");
  });

  it("returns a new version to HASHED so it can be signed again", () => {
    expect(canTransition("VERSIONED", "HASHED")).toBe(true);
  });

  it("allows repeated verification", () => {
    expect(canTransition("VERIFIED", "VERIFIED")).toBe(true);
  });
});

describe("illegal transitions", () => {
  it("cannot skip hashing to reach signed", () => {
    expect(canTransition("UPLOADED", "SIGNED")).toBe(false);
    expect(() => assertTransition("UPLOADED", "SIGNED")).toThrow(InvalidTransitionError);
  });

  it("cannot verify a document that was never signed", () => {
    expect(canTransition("HASHED", "VERIFIED")).toBe(false);
  });

  it("cannot go backwards from signed to hashed without a new version", () => {
    expect(canTransition("SIGNED", "HASHED")).toBe(false);
  });

  it("reports the offending pair in the error message", () => {
    expect(() => assertTransition("ARCHIVED", "SIGNED")).toThrow(/ARCHIVED -> SIGNED/);
  });
});

describe("terminal states", () => {
  it.each(["ARCHIVED", "REVOKED"] as const)("%s accepts no further transitions", (state) => {
    expect(isTerminal(state)).toBe(true);
    expect(nextStates(state)).toHaveLength(0);
    for (const target of DOCUMENT_STATES) {
      expect(canTransition(state, target)).toBe(false);
    }
  });

  it("every non-terminal state past HASHED can be archived or revoked", () => {
    for (const state of ["HASHED", "SIGNED", "STORED", "VERIFIED", "VERSIONED"] as const) {
      expect(canTransition(state, "ARCHIVED")).toBe(true);
      expect(canTransition(state, "REVOKED")).toBe(true);
    }
  });
});

describe("state machine shape", () => {
  it("every declared state has a transition entry, and every target is a declared state", () => {
    for (const state of DOCUMENT_STATES) {
      const targets = nextStates(state as DocumentState);
      expect(Array.isArray(targets)).toBe(true);
      for (const target of targets) expect(DOCUMENT_STATES).toContain(target);
    }
  });
});
