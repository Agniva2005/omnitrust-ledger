// Security Lab: the scenario catalogue. Plain data, safe to send to the browser. Each entry
// states the attack, the control expected to stop it, and the exact result that counts as
// the control holding. lib/security-lab/scenarios.ts implements them against real services.

export type ScenarioCategory = "control" | "documents" | "signatures" | "pki" | "audit" | "authentication";

export type ScenarioDefinition = {
  id: string;
  title: string;
  category: ScenarioCategory;
  attack: string;
  defence: string;
  expected: string;
};

export const SCENARIOS: readonly ScenarioDefinition[] = [
  {
    id: "control-untouched",
    title: "Control: an untouched signed document",
    category: "control",
    attack: "No attack. A document is signed and verified unchanged.",
    defence: "Shows the lab is not rigged to report failures: an honest document must verify.",
    expected: "Verdict VALID",
  },
  {
    id: "document-substitution",
    title: "Substitute the stored document",
    category: "documents",
    attack: "After signing, replace the stored bytes with different, validly encrypted content (as an attacker holding the storage key could).",
    defence: "Verification recomputes SHA-256 from the stored bytes and compares it with the signed hash.",
    expected: "INVALID / HASH_MISMATCH",
  },
  {
    id: "ciphertext-bitflip",
    title: "Flip one bit of the encrypted blob",
    category: "documents",
    attack: "Flip a single bit of the AES-256-GCM ciphertext on disk.",
    defence: "The GCM authentication tag fails, which verification reports as tampering.",
    expected: "INVALID / HASH_MISMATCH",
  },
  {
    id: "signature-corruption",
    title: "Corrupt the signature value",
    category: "signatures",
    attack: "Flip a bit in the stored signature bytes.",
    defence: "Cryptographic verification under the certificate's public key.",
    expected: "INVALID / SIGNATURE_INVALID",
  },
  {
    id: "signature-replay",
    title: "Replay a genuine signature onto another document",
    category: "signatures",
    attack: "Copy a real signature (and its time-stamp) from one document to another signed by the same certificate.",
    defence: "The signature covers the document's own hash, so it does not verify for different content.",
    expected: "INVALID / SIGNATURE_INVALID",
  },
  {
    id: "algorithm-confusion",
    title: "Relabel the signature algorithm",
    category: "signatures",
    attack: "Relabel both the signature and certificate records as a different registered algorithm.",
    defence: "The algorithm is identified from the certificate's key material, and providers refuse foreign keys.",
    expected: "INVALID / ALGORITHM_MISMATCH",
  },
  {
    id: "key-substitution",
    title: "Point the signature at another certificate",
    category: "signatures",
    attack: "Repoint the signature record at a certificate holding a key of a different algorithm.",
    defence: "Key-to-record consistency is checked before any cryptographic operation.",
    expected: "INVALID / ALGORITHM_MISMATCH",
  },
  {
    id: "compromised-key",
    title: "Keep using a signature after key compromise",
    category: "pki",
    attack: "The signing key is reported compromised (no known compromise time) after the document was signed.",
    defence: "Revocation is read from the CA-signed CRL under the timestamp-aware policy.",
    expected: "INVALID / CERTIFICATE_REVOKED",
  },
  {
    id: "timestamp-swap",
    title: "Swap in another signature's time-stamp",
    category: "pki",
    attack: "Attach a genuine RFC 3161 token issued for a different signature, to borrow its time.",
    defence: "The token's message imprint must equal SHA-256 of this signature value.",
    expected: "INVALID / TIMESTAMP_INVALID",
  },
  {
    id: "forged-crl",
    title: "Forge the revocation list",
    category: "pki",
    attack: "Alter the stored CRL so a revoked certificate could appear unrevoked.",
    defence: "A CRL is used only after its CA signature, issuer and freshness check; otherwise status is unavailable.",
    expected: "UNVERIFIABLE / REVOCATION_STATUS_UNAVAILABLE, never VALID",
  },
  {
    id: "cms-content-tamper",
    title: "Verify an exported CMS signature against altered content",
    category: "signatures",
    attack: "Present the detached CMS signature with a document whose bytes were changed.",
    defence: "The signed message-digest attribute covers the exact document bytes.",
    expected: "CMS verification INVALID",
  },
  {
    id: "audit-row-edit",
    title: "Edit an audit log row",
    category: "audit",
    attack: "Change the details of one stored audit entry directly in the database.",
    defence: "The hash chain: each entry's hash covers its fields and its predecessor's hash.",
    expected: "Integrity check fails at exactly that entry",
  },
  {
    id: "audit-consistent-rewrite",
    title: "Rewrite the audit log and recompute every hash",
    category: "audit",
    attack: "Edit an entry, then recompute and rewrite every later hash so the chain verifies.",
    defence: "A signed, time-stamped checkpoint committed to the original chain head.",
    expected: "Chain check fooled, checkpoint check reports LOG_REWRITTEN",
  },
  {
    id: "audit-truncation",
    title: "Delete the newest audit entries",
    category: "audit",
    attack: "Delete entries from the end of the log, which leaves a valid-looking chain.",
    defence: "A signed checkpoint covering those entries.",
    expected: "Chain check fooled, checkpoint check reports LOG_TRUNCATED",
  },
  {
    id: "login-brute-force",
    title: "Brute-force a password",
    category: "authentication",
    attack: "Try wrong passwords repeatedly, then the correct one.",
    defence: "Per-account failed-login throttling, applied before the password is checked.",
    expected: "Locked out after 5 failures, even with the correct password",
  },
];

export function isScenarioId(value: unknown): value is string {
  return typeof value === "string" && SCENARIOS.some((scenario) => scenario.id === value);
}

export type ScenarioOutcome = "HELD" | "FAILED" | "ERROR";

export type ScenarioResult = {
  id: string;
  title: string;
  /** HELD: the control behaved as expected. FAILED: it did not. ERROR: the scenario could not run. */
  outcome: ScenarioOutcome;
  expected: string;
  observed: string;
  steps: string[];
  evidence: Record<string, unknown>;
};
