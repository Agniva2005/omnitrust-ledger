// The timestamp-aware revocation policy, exhaustively. Every reason is checked with no
// proof of existence, a proof before the relevant event, a proof after it, and a proof
// whose accuracy window straddles it.
import { describe, expect, it } from "vitest";
import {
  COMPROMISE_REASONS,
  REVOCATION_REASONS,
  REVOCATION_REASON_CODES,
  evaluateRevocation,
  reasonFromCode,
  type ProofOfExistence,
  type RevocationReason,
} from "@/lib/pki/revocation";

const REVOKED_AT = new Date("2026-06-01T12:00:00Z");
const INVALID_FROM = new Date("2026-05-01T12:00:00Z");

const proofAt = (iso: string, accuracyMs = 1000): ProofOfExistence => ({
  time: new Date(iso),
  accuracyMs,
});

const NON_COMPROMISE = REVOCATION_REASONS.filter((reason) => !COMPROMISE_REASONS.includes(reason));

describe("a certificate that is not revoked", () => {
  it("passes with or without proof of existence", () => {
    expect(evaluateRevocation(null, null).code).toBe("NOT_REVOKED");
    expect(evaluateRevocation(null, proofAt("2026-01-01T00:00:00Z")).verdict).toBe("PASS");
  });
});

describe.each(REVOCATION_REASONS)("revoked for %s", (reason) => {
  it("is indeterminate without proof of existence (REVOKED_NO_POE)", () => {
    const decision = evaluateRevocation({ reason, revokedAt: REVOKED_AT, invalidityDate: null }, null);
    expect(decision.verdict).toBe("INDETERMINATE");
    expect(decision.code).toBe("REVOKED_NO_PROOF_OF_EXISTENCE");
  });
});

describe.each(NON_COMPROMISE)("revoked for %s (not a compromise)", (reason) => {
  const revocation = { reason, revokedAt: REVOKED_AT, invalidityDate: null };

  it("keeps a signature proven to predate the revocation", () => {
    const decision = evaluateRevocation(revocation, proofAt("2026-05-31T12:00:00Z"));
    expect(decision.verdict).toBe("PASS");
    expect(decision.code).toBe("SIGNED_BEFORE_REVOCATION");
  });

  it("rejects a signature made after the revocation", () => {
    const decision = evaluateRevocation(revocation, proofAt("2026-06-02T12:00:00Z"));
    expect(decision.verdict).toBe("INVALID");
    expect(decision.code).toBe("SIGNED_AFTER_REVOCATION");
  });

  it("uses an earlier invalidity date when one was recorded", () => {
    const decision = evaluateRevocation(
      { reason, revokedAt: REVOKED_AT, invalidityDate: INVALID_FROM },
      proofAt("2026-05-15T12:00:00Z"),
    );
    expect(decision.code).toBe("SIGNED_AFTER_REVOCATION");
  });
});

describe.each(COMPROMISE_REASONS)("revoked for %s (a compromise)", (reason) => {
  it("rejects every signature when the compromise time is unknown, even one made long before", () => {
    const decision = evaluateRevocation(
      { reason, revokedAt: REVOKED_AT, invalidityDate: null },
      proofAt("2025-01-01T00:00:00Z"),
    );
    expect(decision.verdict).toBe("INVALID");
    expect(decision.code).toBe("COMPROMISE_TIME_UNKNOWN");
  });

  it("keeps a signature proven to predate the recorded compromise", () => {
    const decision = evaluateRevocation(
      { reason, revokedAt: REVOKED_AT, invalidityDate: INVALID_FROM },
      proofAt("2026-04-30T12:00:00Z"),
    );
    expect(decision.verdict).toBe("PASS");
    expect(decision.code).toBe("SIGNED_BEFORE_COMPROMISE");
  });

  it("rejects a signature made after the recorded compromise but before the revocation", () => {
    const decision = evaluateRevocation(
      { reason, revokedAt: REVOKED_AT, invalidityDate: INVALID_FROM },
      proofAt("2026-05-15T12:00:00Z"),
    );
    expect(decision.verdict).toBe("INVALID");
    expect(decision.code).toBe("SIGNED_AFTER_COMPROMISE");
  });
});

describe("time-stamp accuracy never favours the signature", () => {
  const revocation = { reason: "superseded" as RevocationReason, revokedAt: REVOKED_AT, invalidityDate: null };

  it("rejects a proof whose accuracy window reaches the revocation time", () => {
    // genTime is 500 ms before the revocation, but the stated accuracy is one second.
    const decision = evaluateRevocation(revocation, proofAt("2026-06-01T11:59:59.500Z", 1000));
    expect(decision.code).toBe("SIGNED_AFTER_REVOCATION");
  });

  it("accepts the same genTime when the accuracy window ends before the revocation", () => {
    const decision = evaluateRevocation(revocation, proofAt("2026-06-01T11:59:59.500Z", 100));
    expect(decision.code).toBe("SIGNED_BEFORE_REVOCATION");
  });

  it("treats a proof exactly at the revocation time as not before it", () => {
    expect(evaluateRevocation(revocation, proofAt("2026-06-01T12:00:00Z", 0)).code).toBe(
      "SIGNED_AFTER_REVOCATION",
    );
  });
});

describe("explanations", () => {
  it("say why, naming the reason and the times involved", () => {
    const decision = evaluateRevocation(
      { reason: "affiliationChanged", revokedAt: REVOKED_AT, invalidityDate: null },
      proofAt("2026-05-31T12:00:00Z"),
    );
    expect(decision.explanation).toContain("affiliationChanged");
    expect(decision.explanation).toContain(REVOKED_AT.toISOString());
    expect(decision.explanation).toMatch(/remains valid/);
  });
});

describe("RFC 5280 reason codes", () => {
  it("round-trip between names and CRL codes, with an absent code meaning unspecified", () => {
    for (const reason of REVOCATION_REASONS) {
      expect(reasonFromCode(REVOCATION_REASON_CODES[reason])).toBe(reason);
    }
    expect(reasonFromCode(undefined)).toBe("unspecified");
  });

  it("do not accept certificateHold (6) or removeFromCRL (8), which this CA does not issue", () => {
    expect(reasonFromCode(6)).toBeNull();
    expect(reasonFromCode(8)).toBeNull();
  });
});
