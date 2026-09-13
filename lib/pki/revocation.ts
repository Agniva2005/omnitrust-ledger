// PKI layer: revocation reasons (RFC 5280) and the timestamp-aware revocation policy.
//
// Pure logic with no imports, so it can run in the browser (the revoke form lists the
// reasons) and be tested exhaustively on its own.
//
// Grounding, and where OmniTrust adds its own policy:
//
// - Reason codes and the invalidity date are RFC 5280 sections 5.3.1 and 5.3.2. The
//   invalidity date is "the date on which it is known or suspected that the private key
//   was compromised or that the certificate otherwise became invalid".
// - A revoked certificate with no proof of existence (POE) of the signature before the
//   revocation is indeterminate, not failed. This follows the REVOKED_NO_POE
//   sub-indication of ETSI EN 319 102-1, where a signature time-stamp earlier than the
//   revocation allows past signature validation to succeed.
// - OmniTrust policy, stated rather than claimed as standard: for compromise reasons the
//   POE must precede the invalidity date, and if no invalidity date was recorded the
//   compromise time is unknown, so the signature is treated as invalid.
// - A POE counts as "before" an event only when its time plus the time-stamp's stated
//   accuracy is strictly earlier than the event. Uncertainty never favours the signature.

export const REVOCATION_POLICY_ID = "omnitrust-timestamp-aware-revocation/1";

/** RFC 5280 CRLReason values this CA issues. certificateHold/removeFromCRL are not supported. */
export const REVOCATION_REASONS = [
  "unspecified",
  "keyCompromise",
  "cACompromise",
  "affiliationChanged",
  "superseded",
  "cessationOfOperation",
  "privilegeWithdrawn",
  "aACompromise",
] as const;

export type RevocationReason = (typeof REVOCATION_REASONS)[number];

export const REVOCATION_REASON_CODES: Record<RevocationReason, number> = {
  unspecified: 0,
  keyCompromise: 1,
  cACompromise: 2,
  affiliationChanged: 3,
  superseded: 4,
  cessationOfOperation: 5,
  privilegeWithdrawn: 9,
  aACompromise: 10,
};

export const REVOCATION_REASON_DESCRIPTIONS: Record<RevocationReason, string> = {
  unspecified: "No reason given",
  keyCompromise: "The subject's private key is known or suspected to be compromised",
  cACompromise: "The issuing CA's key is known or suspected to be compromised",
  affiliationChanged: "The subject's name or affiliation changed; the key is not compromised",
  superseded: "The certificate has been replaced; the key is not compromised",
  cessationOfOperation: "The certificate is no longer needed; the key is not compromised",
  privilegeWithdrawn: "A privilege asserted by the certificate was withdrawn",
  aACompromise: "The attribute authority's key is known or suspected to be compromised",
};

export const COMPROMISE_REASONS: readonly RevocationReason[] = [
  "keyCompromise",
  "cACompromise",
  "aACompromise",
];

export function isRevocationReason(value: unknown): value is RevocationReason {
  return typeof value === "string" && (REVOCATION_REASONS as readonly string[]).includes(value);
}

export function assertRevocationReason(value: unknown): RevocationReason {
  if (!isRevocationReason(value)) throw new Error(`Unsupported revocation reason: ${String(value)}`);
  return value;
}

/** Maps a CRL reason code to its name; null for codes this CA does not issue. */
export function reasonFromCode(code: number | undefined): RevocationReason | null {
  if (code === undefined) return "unspecified";
  const match = (Object.entries(REVOCATION_REASON_CODES) as [RevocationReason, number][]).find(
    ([, value]) => value === code,
  );
  return match ? match[0] : null;
}

export type RevocationRecord = {
  reason: RevocationReason;
  revokedAt: Date;
  invalidityDate: Date | null;
};

export type ProofOfExistence = {
  /** The time the signature is proven to have existed, e.g. a verified time-stamp's genTime. */
  time: Date;
  /** The time-stamp's stated accuracy; the POE's latest possible time is time + accuracy. */
  accuracyMs: number;
};

export type RevocationDecisionCode =
  | "NOT_REVOKED"
  | "SIGNED_BEFORE_REVOCATION"
  | "SIGNED_BEFORE_COMPROMISE"
  | "SIGNED_AFTER_REVOCATION"
  | "SIGNED_AFTER_COMPROMISE"
  | "COMPROMISE_TIME_UNKNOWN"
  | "REVOKED_NO_PROOF_OF_EXISTENCE";

export type RevocationDecision = {
  /** PASS: acceptable. INVALID: positive evidence against. INDETERMINATE: cannot be decided. */
  verdict: "PASS" | "INVALID" | "INDETERMINATE";
  code: RevocationDecisionCode;
  explanation: string;
};

function latestPossible(proof: ProofOfExistence): Date {
  return new Date(proof.time.getTime() + Math.max(0, proof.accuracyMs));
}

export function evaluateRevocation(
  revocation: RevocationRecord | null,
  proof: ProofOfExistence | null,
): RevocationDecision {
  if (!revocation) {
    return { verdict: "PASS", code: "NOT_REVOKED", explanation: "The signing certificate is not revoked." };
  }

  const revoked = `revoked ${revocation.revokedAt.toISOString()} for ${revocation.reason}`;

  if (!proof) {
    return {
      verdict: "INDETERMINATE",
      code: "REVOKED_NO_PROOF_OF_EXISTENCE",
      explanation:
        `The signing certificate was ${revoked}, and there is no trusted time-stamp proving the ` +
        "signature existed before that, so its validity at signing time cannot be established.",
    };
  }

  const proofTime = latestPossible(proof).toISOString();

  if (COMPROMISE_REASONS.includes(revocation.reason)) {
    if (!revocation.invalidityDate) {
      return {
        verdict: "INVALID",
        code: "COMPROMISE_TIME_UNKNOWN",
        explanation:
          `The signing certificate was ${revoked} with no recorded invalidity date, so the key may ` +
          "have been compromised before the signature was made. Under this policy the signature is not trusted.",
      };
    }
    const compromise = revocation.invalidityDate;
    if (latestPossible(proof) < compromise) {
      return {
        verdict: "PASS",
        code: "SIGNED_BEFORE_COMPROMISE",
        explanation:
          `The signature is proven to exist by ${proofTime}, before the key's recorded compromise at ` +
          `${compromise.toISOString()}. The certificate was later ${revoked}; the signature remains valid under this policy.`,
      };
    }
    return {
      verdict: "INVALID",
      code: "SIGNED_AFTER_COMPROMISE",
      explanation:
        `The key is recorded as compromised from ${compromise.toISOString()}, and the signature cannot be ` +
        `proven to predate that (latest possible time ${proofTime}). It may have been made with the compromised key.`,
    };
  }

  const effective =
    revocation.invalidityDate && revocation.invalidityDate < revocation.revokedAt
      ? revocation.invalidityDate
      : revocation.revokedAt;

  if (latestPossible(proof) < effective) {
    return {
      verdict: "PASS",
      code: "SIGNED_BEFORE_REVOCATION",
      explanation:
        `The signature is proven to exist by ${proofTime}, while the certificate was still valid. The ` +
        `certificate was later ${revoked}, which does not indicate key compromise, so the historical signature remains valid.`,
    };
  }

  return {
    verdict: "INVALID",
    code: "SIGNED_AFTER_REVOCATION",
    explanation:
      `The certificate was invalid from ${effective.toISOString()} (${revocation.reason}), and the signature cannot ` +
      `be proven to predate that (latest possible time ${proofTime}).`,
  };
}
