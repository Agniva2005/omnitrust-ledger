// Document lifecycle, CLAUDE.md Section 3 / report Figure 4:
//   created -> uploaded -> hashed -> signed -> stored -> verified -> versioned
//            -> archived | revoked

export const DOCUMENT_STATES = [
  "CREATED",
  "UPLOADED",
  "HASHED",
  "SIGNED",
  "STORED",
  "VERIFIED",
  "VERSIONED",
  "ARCHIVED",
  "REVOKED",
] as const;

export type DocumentState = (typeof DOCUMENT_STATES)[number];

const TERMINAL: readonly DocumentState[] = ["ARCHIVED", "REVOKED"];

const TRANSITIONS: Record<DocumentState, readonly DocumentState[]> = {
  CREATED: ["UPLOADED"],
  UPLOADED: ["HASHED"],
  HASHED: ["SIGNED", "VERSIONED", "ARCHIVED", "REVOKED"],
  SIGNED: ["STORED", "VERSIONED", "ARCHIVED", "REVOKED"],
  // Verification is idempotent and repeatable, so STORED -> VERIFIED and
  // VERIFIED -> VERIFIED are both legal.
  STORED: ["VERIFIED", "VERSIONED", "ARCHIVED", "REVOKED"],
  VERIFIED: ["VERIFIED", "VERSIONED", "ARCHIVED", "REVOKED"],
  // A new version returns the document to HASHED: fresh bytes, hashed, unsigned.
  VERSIONED: ["HASHED", "ARCHIVED", "REVOKED"],
  ARCHIVED: [],
  REVOKED: [],
};

export class InvalidTransitionError extends Error {
  readonly status = 409;
  constructor(from: DocumentState, to: DocumentState) {
    super(`Illegal document lifecycle transition: ${from} -> ${to}`);
    this.name = "InvalidTransitionError";
  }
}

export function isDocumentState(value: unknown): value is DocumentState {
  return typeof value === "string" && (DOCUMENT_STATES as readonly string[]).includes(value);
}

export function assertDocumentState(value: unknown): DocumentState {
  if (!isDocumentState(value)) throw new Error(`Unknown document state: ${String(value)}`);
  return value;
}

export function isTerminal(state: DocumentState): boolean {
  return TERMINAL.includes(state);
}

export function canTransition(from: DocumentState, to: DocumentState): boolean {
  return TRANSITIONS[from].includes(to);
}

export function nextStates(from: DocumentState): readonly DocumentState[] {
  return TRANSITIONS[from];
}

/** Returns `to` if the transition is legal, throws InvalidTransitionError otherwise. */
export function assertTransition(from: DocumentState, to: DocumentState): DocumentState {
  if (!canTransition(from, to)) throw new InvalidTransitionError(from, to);
  return to;
}

/**
 * Walks a sequence of states, asserting each hop. Used where one operation moves a
 * document through several states at once (upload runs CREATED -> UPLOADED -> HASHED).
 */
export function assertPath(path: readonly DocumentState[]): DocumentState {
  if (path.length === 0) throw new Error("Empty lifecycle path");
  for (let index = 1; index < path.length; index += 1) {
    assertTransition(path[index - 1], path[index]);
  }
  return path[path.length - 1];
}
