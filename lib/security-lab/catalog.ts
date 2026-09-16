// Security Lab: the scenario catalogue. Plain data, safe to send to the browser. Each entry
// states the attack, the control expected to stop it, and the exact result that counts as
// the control holding. lib/security-lab/scenarios.ts implements them against real services.

export type ScenarioCategory = "control" | "documents" | "signatures" | "pki" | "keys" | "audit" | "authentication";

/**
 * What an adversary can do. The in-scope capabilities are the ones scenarios grant and test;
 * the others are stated in docs/threat-model.md as outside what this installation defends against,
 * so the Security Lab's results are never read as covering them.
 */
export type AdversaryId =
  | "none"
  | "storage-write"
  | "database-write"
  | "artefact-replay"
  | "offline-content"
  | "key-compromise"
  | "online-guessing"
  | "file-theft"
  | "host-compromise"
  | "ca-key-compromise"
  | "network"
  | "denial-of-service"
  | "side-channel";

export type Adversary = {
  id: AdversaryId;
  label: string;
  capability: string;
  inScope: boolean;
  /** For out-of-scope capabilities: what it could achieve here, stated plainly. */
  consequence?: string;
};

export const ADVERSARIES: readonly Adversary[] = [
  { id: "none", label: "No adversary", capability: "Nothing is altered: the honest-path control.", inScope: true },
  {
    id: "storage-write",
    label: "Storage write",
    capability: "Replaces or alters the encrypted document blobs on disk, possibly holding the storage encryption key.",
    inScope: true,
  },
  {
    id: "database-write",
    label: "Database write",
    capability: "Edits, relabels, re-points or deletes rows in the database (signatures, certificates, CRLs, audit entries) without the private keys of the CA, the TSA or the audit signer.",
    inScope: true,
  },
  {
    id: "artefact-replay",
    label: "Artefact replay",
    capability: "Copies genuine, correctly signed artefacts (signature values, time-stamp tokens) from one record to another.",
    inScope: true,
  },
  {
    id: "offline-content",
    label: "Offline content substitution",
    capability: "Presents an exported signature to an offline verifier together with content other than what was signed.",
    inScope: true,
  },
  {
    id: "key-compromise",
    label: "Signer key compromise",
    capability: "Obtains a signer's private key after it signed; the compromise is reported and the certificate revoked.",
    inScope: true,
  },
  {
    id: "online-guessing",
    label: "Online password guessing",
    capability: "Submits login attempts over HTTP against a known account.",
    inScope: true,
  },
  {
    id: "file-theft",
    label: "Copied files",
    capability: "Obtains a copy of the database, the document storage and the master key file, but not the key's passphrase or the Windows account that protects it.",
    inScope: true,
  },
  {
    id: "host-compromise",
    label: "Host compromise",
    capability: "Reads the database, the storage directory and the master key together, or runs code inside the application process.",
    inScope: false,
    consequence:
      "Can decrypt every private key and so sign documents, issue certificates and forge audit checkpoints. Only an anchor recorded outside the host could reveal a rewritten history.",
  },
  {
    id: "ca-key-compromise",
    label: "CA key compromise",
    capability: "Obtains the root CA's private key.",
    inScope: false,
    consequence: "Can issue certificates and CRLs that verify. There is no offline root, intermediate CA or certificate transparency to detect it.",
  },
  {
    id: "network",
    label: "Network attacker",
    capability: "Observes or modifies traffic between the browser and the server.",
    inScope: false,
    consequence: "TLS is a deployment concern outside the application; the session cookie is marked secure only in production builds.",
  },
  {
    id: "denial-of-service",
    label: "Denial of service",
    capability: "Exhausts CPU, memory, storage or the login throttle.",
    inScope: false,
    consequence: "Not evaluated. The per-account login lock can itself be used to lock a known account out.",
  },
  {
    id: "side-channel",
    label: "Side channels",
    capability: "Measures timing, cache or power behaviour of the cryptographic implementations.",
    inScope: false,
    consequence: "Not evaluated; the providers rely on OpenSSL and the noble libraries, whose own claims are not re-tested here.",
  },
];

/** The security property a scenario attacks. */
export type SecurityProperty =
  | "none (control)"
  | "document integrity"
  | "signature authenticity"
  | "algorithm binding"
  | "revocation"
  | "time of existence"
  | "log integrity"
  | "key confidentiality"
  | "authentication";

export type ScenarioDefinition = {
  id: string;
  title: string;
  category: ScenarioCategory;
  /** The capability the attack uses; always an in-scope entry of ADVERSARIES. */
  adversary: AdversaryId;
  property: SecurityProperty;
  attack: string;
  defence: string;
  expected: string;
  /**
   * Whether the scenario's subject can be a document chosen in the application rather than
   * content the sandbox invents. Only scenarios whose subject *is* a document qualify: the
   * audit and authentication ones attack the log and the login, where a document is irrelevant.
   */
  acceptsSubject?: boolean;
};

export function adversaryFor(id: AdversaryId): Adversary {
  const adversary = ADVERSARIES.find((candidate) => candidate.id === id);
  if (!adversary) throw new Error(`Unknown adversary ${id}`);
  return adversary;
}

export const SCENARIOS: readonly ScenarioDefinition[] = [
  {
    id: "control-untouched",
    acceptsSubject: true,
    adversary: "none",
    property: "none (control)",
    title: "Control: an untouched signed document",
    category: "control",
    attack: "No attack. A document is signed and verified unchanged.",
    defence: "Shows the lab is not rigged to report failures: an honest document must verify.",
    expected: "Verdict VALID",
  },
  {
    id: "document-substitution",
    acceptsSubject: true,
    adversary: "storage-write",
    property: "document integrity",
    title: "Substitute the stored document",
    category: "documents",
    attack: "After signing, replace the stored bytes with different, validly encrypted content (as an attacker holding the storage key could).",
    defence: "Verification recomputes SHA-256 from the stored bytes and compares it with the signed hash.",
    expected: "INVALID / HASH_MISMATCH",
  },
  {
    id: "ciphertext-bitflip",
    acceptsSubject: true,
    adversary: "storage-write",
    property: "document integrity",
    title: "Flip one bit of the encrypted blob",
    category: "documents",
    attack: "Flip a single bit of the AES-256-GCM ciphertext on disk.",
    defence: "The GCM authentication tag fails, which verification reports as tampering.",
    expected: "INVALID / HASH_MISMATCH",
  },
  {
    id: "signature-corruption",
    acceptsSubject: true,
    adversary: "database-write",
    property: "signature authenticity",
    title: "Corrupt the signature value",
    category: "signatures",
    attack: "Flip a bit in the stored signature bytes.",
    defence: "Cryptographic verification under the certificate's public key.",
    expected: "INVALID / SIGNATURE_INVALID",
  },
  {
    id: "signature-replay",
    acceptsSubject: true,
    adversary: "artefact-replay",
    property: "signature authenticity",
    title: "Replay a genuine signature onto another document",
    category: "signatures",
    attack: "Copy a real signature (and its time-stamp) from one document to another signed by the same certificate.",
    defence: "The signature covers the document's own hash, so it does not verify for different content.",
    expected: "INVALID / SIGNATURE_INVALID",
  },
  {
    id: "algorithm-confusion",
    acceptsSubject: true,
    adversary: "database-write",
    property: "algorithm binding",
    title: "Relabel the signature algorithm",
    category: "signatures",
    attack: "Relabel both the signature and certificate records as a different registered algorithm.",
    defence: "The algorithm is identified from the certificate's key material, and providers refuse foreign keys.",
    expected: "INVALID / ALGORITHM_MISMATCH",
  },
  {
    id: "key-substitution",
    acceptsSubject: true,
    adversary: "database-write",
    property: "algorithm binding",
    title: "Point the signature at another certificate",
    category: "signatures",
    attack: "Repoint the signature record at a certificate holding a key of a different algorithm.",
    defence: "Key-to-record consistency is checked before any cryptographic operation.",
    expected: "INVALID / ALGORITHM_MISMATCH",
  },
  {
    id: "compromised-key",
    acceptsSubject: true,
    adversary: "key-compromise",
    property: "revocation",
    title: "Keep using a signature after key compromise",
    category: "pki",
    attack: "The signing key is reported compromised (no known compromise time) after the document was signed.",
    defence: "Revocation is read from the CA-signed CRL under the timestamp-aware policy.",
    expected: "INVALID / CERTIFICATE_REVOKED",
  },
  {
    id: "timestamp-swap",
    adversary: "artefact-replay",
    property: "time of existence",
    title: "Swap in another signature's time-stamp",
    category: "pki",
    attack: "Attach a genuine RFC 3161 token issued for a different signature, to borrow its time.",
    defence: "The token's message imprint must equal SHA-256 of this signature value.",
    expected: "INVALID / TIMESTAMP_INVALID",
  },
  {
    id: "forged-crl",
    adversary: "database-write",
    property: "revocation",
    title: "Forge the revocation list",
    category: "pki",
    attack: "Alter the stored CRL so a revoked certificate could appear unrevoked.",
    defence: "A CRL is used only after its CA signature, issuer and freshness check; otherwise status is unavailable.",
    expected: "UNVERIFIABLE / REVOCATION_STATUS_UNAVAILABLE, never VALID",
  },
  {
    id: "cms-content-tamper",
    adversary: "offline-content",
    property: "document integrity",
    title: "Verify an exported CMS signature against altered content",
    category: "signatures",
    attack: "Present the detached CMS signature with a document whose bytes were changed.",
    defence: "The signed message-digest attribute covers the exact document bytes.",
    expected: "CMS verification INVALID",
  },
  {
    id: "stolen-key-file",
    adversary: "file-theft",
    property: "key confidentiality",
    title: "Steal a copy of a protected master key file",
    category: "keys",
    attack: "Copy a passphrase-protected master key file together with the database holding the encrypted private keys, then try to unwrap it with no passphrase and with a guessed one.",
    defence: "The file holds the master key wrapped with AES-256-GCM under a scrypt-derived key (lib/crypto/key-custody.ts); without the passphrase it does not unwrap.",
    expected: "Refused without the passphrase and with a guessed one; the right passphrase recovers the same key",
  },
  {
    id: "audit-row-edit",
    adversary: "database-write",
    property: "log integrity",
    title: "Edit an audit log row",
    category: "audit",
    attack: "Change the details of one stored audit entry directly in the database.",
    defence: "The hash chain: each entry's hash covers its fields and its predecessor's hash.",
    expected: "Integrity check fails at exactly that entry",
  },
  {
    id: "audit-consistent-rewrite",
    adversary: "database-write",
    property: "log integrity",
    title: "Rewrite the audit log and recompute every hash",
    category: "audit",
    attack: "Edit an entry, then recompute and rewrite every later hash so the chain verifies.",
    defence: "A signed, time-stamped checkpoint committed to the original chain head.",
    expected: "Chain check fooled, checkpoint check reports LOG_REWRITTEN",
  },
  {
    id: "audit-truncation",
    adversary: "database-write",
    property: "log integrity",
    title: "Delete the newest audit entries",
    category: "audit",
    attack: "Delete entries from the end of the log, which leaves a valid-looking chain.",
    defence: "A signed checkpoint covering those entries.",
    expected: "Chain check fooled, checkpoint check reports LOG_TRUNCATED",
  },
  {
    id: "login-brute-force",
    adversary: "online-guessing",
    property: "authentication",
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
