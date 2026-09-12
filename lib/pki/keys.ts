// Key lifecycle, report Figure 7, aligned to the NIST SP 800-57 key states:
//   generated -> active -> rotated -> revoked -> retired
//
// Also holds the certificate lifecycle (Figure 6), since the two move together.

export const KEY_STATES = ["GENERATED", "ACTIVE", "ROTATED", "REVOKED", "RETIRED"] as const;
export type KeyState = (typeof KEY_STATES)[number];

const KEY_TRANSITIONS: Record<KeyState, readonly KeyState[]> = {
  // GENERATED exists for the moment between key generation and persistence; a key is
  // stored as ACTIVE. Modelled explicitly so the Figure 7 path is complete.
  GENERATED: ["ACTIVE"],
  ACTIVE: ["ROTATED", "REVOKED"],
  ROTATED: ["REVOKED", "RETIRED"],
  REVOKED: ["RETIRED"],
  RETIRED: [],
};

export const CERTIFICATE_STATES = ["REQUESTED", "ACTIVE", "EXPIRED", "REVOKED"] as const;
export type CertificateState = (typeof CERTIFICATE_STATES)[number];

const CERTIFICATE_TRANSITIONS: Record<CertificateState, readonly CertificateState[]> = {
  // Figure 6: requested -> issued -> active -> renewed -> expired | revoked.
  // Renewal issues a new certificate rather than mutating one, so it appears here as
  // the old certificate moving to EXPIRED or REVOKED.
  REQUESTED: ["ACTIVE"],
  ACTIVE: ["EXPIRED", "REVOKED"],
  EXPIRED: ["REVOKED"],
  REVOKED: [],
};

export class InvalidKeyTransitionError extends Error {
  readonly status = 409;
  constructor(from: string, to: string, kind: "key" | "certificate") {
    super(`Illegal ${kind} lifecycle transition: ${from} -> ${to}`);
    this.name = "InvalidKeyTransitionError";
  }
}

export function isKeyState(value: unknown): value is KeyState {
  return typeof value === "string" && (KEY_STATES as readonly string[]).includes(value);
}

export function assertKeyState(value: unknown): KeyState {
  if (!isKeyState(value)) throw new Error(`Unknown key state: ${String(value)}`);
  return value;
}

export function isCertificateState(value: unknown): value is CertificateState {
  return typeof value === "string" && (CERTIFICATE_STATES as readonly string[]).includes(value);
}

export function assertCertificateState(value: unknown): CertificateState {
  if (!isCertificateState(value)) throw new Error(`Unknown certificate state: ${String(value)}`);
  return value;
}

export function canTransitionKey(from: KeyState, to: KeyState): boolean {
  return KEY_TRANSITIONS[from].includes(to);
}

export function nextKeyStates(from: KeyState): readonly KeyState[] {
  return KEY_TRANSITIONS[from];
}

export function assertKeyTransition(from: KeyState, to: KeyState): KeyState {
  if (!canTransitionKey(from, to)) throw new InvalidKeyTransitionError(from, to, "key");
  return to;
}

export function canTransitionCertificate(from: CertificateState, to: CertificateState): boolean {
  return CERTIFICATE_TRANSITIONS[from].includes(to);
}

export function nextCertificateStates(from: CertificateState): readonly CertificateState[] {
  return CERTIFICATE_TRANSITIONS[from];
}

export function assertCertificateTransition(
  from: CertificateState,
  to: CertificateState,
): CertificateState {
  if (!canTransitionCertificate(from, to)) {
    throw new InvalidKeyTransitionError(from, to, "certificate");
  }
  return to;
}
