# CLAUDE.md — OmniTrust Ledger Build Specification

Save this file as `CLAUDE.md` in the root of a new, empty project directory before starting Claude Code. Claude Code reads this file automatically as persistent project context. This spec is derived directly from an academic Review 1 report and is the authoritative source of truth for what to build — if anything here is ambiguous, make the most defensible engineering choice, state your assumption, and proceed.

---

## 0. What this project is

**OmniTrust Ledger** is a PKI-driven document management system with algorithm-agnostic, multi-algorithm digital signature orchestration. The goal is a **real, runnable, demoable, end-to-end web application** — not a prototype of one module, not a slide deck, not mocked-out crypto. Every cryptographic operation in the running app must be real (via vetted libraries), every signature must actually verify, and every "tamper detected" result must come from an actual altered byte, not a scripted fake.

This is being built to demonstrate, live, the architecture and claims made in an accompanying Review 1 research report (layered architecture, multi-algorithm orchestration, certificate/key lifecycle management, tamper-evident audit logging). Treat the report's Section 9 (System Architecture, Figure 10), Section 10 (Methodology), and Figure 8 (Verification Workflow) as binding specifications, reproduced in full below so you don't need the original file to build correctly.

**Definition of "done" for the whole project:** a person can clone this repo, run three commands, open a browser, and — following `DEMO_SCRIPT.md` — sign a document under three different algorithms, verify it successfully, watch a tampered document get correctly rejected with a specific reason, revoke a certificate and watch verification correctly fail afterward, and view a tamper-evident audit log and a real benchmark table comparing the three algorithms. If that doesn't work from a clean clone, the project is not done, regardless of how much code exists.

---

## 1. Tech stack (decided — do not relitigate unless you hit a hard blocker, and tell me why if you deviate)

- **Framework:** Next.js 14+ (App Router), TypeScript, single monolithic app — no microservices, no docker-compose orchestration. Simplicity of running the demo matters more than architectural fashion.
- **Database:** SQLite via Prisma ORM. Zero external services required to run. Schema should stay Postgres-compatible (avoid SQLite-only features) so it could be migrated later, but don't spend time on that now.
- **Styling/UI:** Tailwind CSS + shadcn/ui components. Functional and clean, not fancy — this is a technical demo, not a marketing site.
- **Auth:** Custom lightweight session auth — bcrypt password hashing, JWT in an httpOnly cookie. No third-party auth provider.
- **Cryptography — use ONLY these, never hand-roll a primitive:**
  - RSA (PSS padding) and ECDSA (P-256) via Node's built-in `node:crypto` module.
  - EdDSA (Ed25519) via `@noble/ed25519` (audited, no native bindings needed).
  - Certificates via `@peculiar/x509` (WebCrypto-based, well-maintained). If you find its API awkward for a self-signed local CA, `node-forge` is an acceptable fallback for certificate/CA operations specifically — but keep actual signing/verification math on the libraries above.
  - Hashing: SHA-256 via `node:crypto`.
- **Testing:** Vitest.
- **Scripting:** `tsx` for one-off scripts (seed, benchmark).
- **Package manager:** npm (or pnpm if you prefer — pick one and be consistent).

Do not introduce Redis, message queues, external object storage, or containerization. This is a single deployable Next.js app with a local SQLite file and a local `storage/` directory for document blobs. That constraint is intentional.

---

## 2. Hard rules (violating these is a bigger problem than any missing feature)

1. **No hand-rolled cryptography, ever.** No custom hash functions, no custom padding schemes, no "simplified" signature math. If a real algorithm is inconvenient to implement correctly, use the library's implementation, not a shortcut.
2. **No algorithm-specific code outside `/lib/crypto/`.** Every other layer (documents, PKI, API routes, UI) must go through the `SignatureOrchestrator` interface. If you catch yourself importing `node:crypto`'s `createSign`/`createVerify` or `@noble/ed25519` anywhere outside `/lib/crypto/`, stop and refactor. This boundary is the entire point of the project.
3. **This is a demo-grade PKI, not a production one — say so, in the UI and the README.** The local Certificate Authority is self-signed and not a trusted root anyone else recognizes; the private-key encryption-at-rest key is a local file, not a KMS/HSM. Do not write documentation or UI copy that overstates the security posture. A "Demo / Not for Production Use" notice belongs in the README and ideally a small footer note in the UI.
4. **Every claim the UI or benchmark page makes must come from a real, reproducible computation in this codebase.** No placeholder numbers, no "illustrative" charts presented as measured data. If something is illustrative rather than measured, label it as such.
5. **Test the security-relevant behavior, not just the happy path.** For every "this should be rejected" case in Section 6 below, there must be an automated test that actually exercises the failure and asserts the correct rejection with the correct reason.
6. **Work in phases, not one giant commit.** Follow Section 5 below in order. After each phase: run the tests, run the build, update `PROGRESS.md` (create it in Phase 0) with what's done and what's next, then commit. Don't start Phase N+1 with Phase N's tests failing.

---

## 3. System architecture (binding — from Review 1, Section 9 / Figure 10)

Seven layers, each depending only on the layer(s) beneath it:

```
Presentation Layer          → Next.js pages + API route handlers (thin — no business logic)
Authentication & Authorization → session, RBAC (roles: ADMIN, SIGNER, VERIFIER, VIEWER)
Document Management Layer   → upload, metadata, versioning, lifecycle state
Cryptographic Orchestration → SignatureOrchestrator + RSA/ECDSA/EdDSA providers (ONLY place algorithm-specific code lives)
PKI Layer                   → local CA, certificate issuance/validation/revocation, key lifecycle
Secure Storage Layer        → encrypted document blobs on disk + DB metadata (no crypto decisions here, only storage)
Audit & Monitoring Layer    → append-only, hash-chained log of every security-relevant event
```

Map this to folders:

```
/lib
  /auth        — session.ts, rbac.ts
  /documents   — lifecycle.ts, storage.ts, service.ts
  /crypto      — types.ts, orchestrator.ts, providers/{rsa,ecdsa,eddsa}.ts   ← ONLY algorithm-specific code here
  /pki         — ca.ts, certificates.ts, keys.ts, validation.ts
  /audit       — log.ts, integrity.ts
/app
  /api/...     — route handlers, call into /lib only, contain no crypto/business logic themselves
  /(routes)... — UI pages
/prisma        — schema.prisma, seed.ts
/scripts       — benchmark.ts
/storage       — encrypted document blobs (gitignored)
/tests         — mirror /lib structure: crypto/, pki/, documents/, verification/, audit/
```

### Document lifecycle (Figure 4)
`created → uploaded → hashed → signed → stored → verified → versioned → archived | revoked`

### Certificate lifecycle (Figure 6)
`requested → issued → active → renewed → expired | revoked`

### Key lifecycle (Figure 7, aligned to NIST SP 800-57 states)
`generated → active → rotated → revoked → retired`

### Verification workflow (Figure 8) — implement this exact sequence, and expose each step's result

1. Retrieve document (and its current hash from DB).
2. Retrieve signature record.
3. Retrieve certificate used to sign.
4. Validate certificate: chain to local CA, validity period (not expired), not revoked.
5. Extract public key from certificate.
6. Recompute the document's hash from the actual stored bytes right now.
7. Verify the signature cryptographically against the recomputed hash using the orchestrator (algorithm resolved from the certificate/signature record, never hard-coded).
8. Compare recomputed hash vs. the hash that was actually signed; combine with step 7's result.

Return a structured result, not just a boolean:
```ts
type VerificationResult = {
  outcome: "AUTHENTIC" | "INVALID";
  reason?: "HASH_MISMATCH" | "SIGNATURE_INVALID" | "CERTIFICATE_EXPIRED" | "CERTIFICATE_REVOKED" | "CERTIFICATE_CHAIN_INVALID";
  steps: { step: string; passed: boolean; detail?: string }[];
};
```
The UI must render these steps as a checklist (this is the centerpiece of the demo — it's showing Figure 8 executing live).

---

## 4. Data model (Prisma — starting schema, adjust field names as needed but keep these entities and relationships)

```
User(id, email, passwordHash, role[ADMIN|SIGNER|VERIFIER|VIEWER], createdAt)

KeyPair(id, ownerUserId, algorithm[RSA|ECDSA_P256|ED25519], publicKeyPem,
        encryptedPrivateKey, status[ACTIVE|ROTATED|REVOKED|RETIRED],
        createdAt, rotatedAt?, revokedAt?)

CertificateAuthority(id, name, certPem, encryptedPrivateKey, createdAt)   // singleton, seeded once

Certificate(id, keyPairId, subjectUserId, issuerCaId, serialNumber,
            algorithm, certPem, issuedAt, expiresAt,
            status[ACTIVE|EXPIRED|REVOKED], revokedAt?, revocationReason?)

Document(id, ownerUserId, filename, mimeType, storagePath, currentHash,
         status[lifecycle enum above], createdAt, updatedAt)

DocumentVersion(id, documentId, versionNumber, storagePath, hash, createdAt)

Signature(id, documentVersionId, certificateId, algorithm, signatureBytes,
          signedAt, signedByUserId)

AuditLogEntry(id, seq, actorUserId?, action, targetType, targetId,
              metadataJson, prevHash, entryHash, createdAt)
```

`AuditLogEntry.entryHash = SHA256(prevHash + serialize(this entry's own fields))`, forming a hash chain from entry 1 onward. Integrity check = walk the chain and recompute.

---

## 5. Build order — execute phases sequentially, in order, each with its own Definition of Done

Do not skip ahead. Do not batch multiple phases into one commit. After each phase, run `npm test` and `npm run build`, update `PROGRESS.md`, commit, then move on. Pause and summarize progress to me after Phase 0, Phase 3, and Phase 6 — those are the highest-risk foundations to sanity-check before building further on top. Otherwise proceed autonomously through the rest.

**Phase 0 — Scaffold**
Next.js + TS + Tailwind + shadcn/ui + Prisma/SQLite + Vitest, initialized. Folder structure from Section 3 created (empty modules with clear TODOs are fine). `PROGRESS.md` created. DoD: `npm run dev` serves a placeholder home page; `npm test` runs (even with 0 tests); `npx prisma migrate dev` works against an empty schema.

**Phase 1 — Auth & RBAC**
Prisma schema for `User`. Login/logout API routes, bcrypt, JWT httpOnly cookie, `getSession()` helper, `requireRole()` RBAC helper. Login page. DoD: seeded test users can log in; a protected test route correctly rejects wrong roles; tests pass.

**Phase 2 — Document management (no crypto yet)**
`Document`/`DocumentVersion` schema. Upload API (multipart), store bytes under `/storage/documents/`, compute SHA-256 on upload, lifecycle state machine with validated transitions. Upload page + document list/detail pages. DoD: upload a file via the UI, see it listed with its real computed hash and status `uploaded`/`hashed`.

**Phase 3 — Cryptographic Orchestration Layer** *(pause for check-in after this phase)*
`SignatureProvider` interface (`sign`, `verify`, `generateKeyPair`). Implement `RsaProvider`, `EcdsaProvider`, `EddsaProvider`. `SignatureOrchestrator` resolves provider by algorithm from a registry — adding a 4th algorithm later should only mean adding one file + one registry line. Unit tests per provider using real, independently-known-correct test vectors (not just round-trip self-consistency — at least confirm output format/lengths match the algorithm's spec, e.g. Ed25519 signatures are exactly 64 bytes). DoD: `npm run test -- crypto` passes for all three algorithms; a boundary test (e.g. a lint/grep script) confirms no algorithm-specific import exists outside `/lib/crypto/`.

**Phase 4 — PKI Layer**
Generate the local root CA once (seed script), self-signed. `KeyPair` and `Certificate` schema. Certificate issuance (generate keypair via the relevant provider, build and sign an X.509 cert with the CA), validation (chain, validity period, revocation status), revocation. Key lifecycle status transitions. Certificate management UI (list, issue, revoke). DoD: issue certificates under all three algorithms for a demo user; revoke one; the validation function correctly flags the revoked one and correctly passes the active ones.

**Phase 5 — Wire signing into the document flow**
`Signature` schema. "Sign" action: pick a certificate (which implies algorithm and key), orchestrator signs the current document hash, store the `Signature` record, advance lifecycle to `signed`/`stored`. Sign UI (cert picker, resulting signature metadata shown). DoD: sign the same logical action across all three algorithms on different documents; DB records are correct; re-fetching and manually recomputing the hash outside the app matches what's stored.

**Phase 6 — Verification workflow** *(pause for check-in after this phase)*
Implement the exact 8-step sequence from Section 3 above, returning the structured `VerificationResult`. Verify UI renders the step checklist live, ending in a clear AUTHENTIC/INVALID badge with reason. Automated tests, each asserting a specific real failure mode:
   - Flip one byte in a stored document's blob → expect `HASH_MISMATCH`.
   - Verify with a certificate that has an expired `expiresAt` → expect `CERTIFICATE_EXPIRED`.
   - Verify after revoking the signing certificate → expect `CERTIFICATE_REVOKED`.
   - Corrupt/mismatch the signature bytes → expect `SIGNATURE_INVALID`.
   - Confirm a document signed under algorithm X fails verification if you (in a test) substitute a different algorithm's public key.
DoD: all five tests above pass against real cryptographic operations (no mocking crypto in these specific tests).

**Phase 7 — Audit & monitoring**
`AuditLogEntry` schema with hash chain as specified in Section 4. Emit entries for: login, upload, sign, verify (both outcomes, with reason), certificate issue/revoke, key lifecycle transitions. Audit log UI with a "Verify Log Integrity" button that walks the chain. A test that corrupts one stored entry and confirms the integrity check detects exactly where the chain breaks. DoD: a realistic sequence of demo actions produces a coherent audit trail; integrity check passes on the untouched log and fails (with the correct break point identified) when a row is tampered with directly in the DB.

**Phase 8 — Benchmarking**
`scripts/benchmark.ts`: run N (e.g. 200) sign+verify cycles per algorithm on a couple of representative payload sizes, measure wall-clock time (mean/median/p95) via `process.hrtime.bigint()`, and record signature byte size and certificate size per algorithm. Write results to a JSON file and render a simple results table (and a small chart if convenient) on a `/benchmarks` page, read from that file. Label results with the machine/environment they were run on and note that absolute numbers are environment-dependent — the comparison across algorithms is the point, not the absolute numbers. DoD: `npm run benchmark` produces a real results file from real measured operations; the `/benchmarks` page renders it.

**Phase 9 — Seed data & demo script**
`prisma/seed.ts`: root CA, three users (`admin@demo`, `signer@demo`, `verifier@demo` — simple fixed demo passwords, documented in README), certificates issued under each of the three algorithms for `signer@demo`, 3–4 sample documents (a mix of unsigned, signed-and-valid under each algorithm, and one pre-tampered example prepared for the canned "invalid" demo moment). Write `DEMO_SCRIPT.md`: a literal, numbered click-through (URLs, buttons, expected results) that a presenter can follow live, explicitly cross-referencing which report figure/section each step demonstrates. DoD: a fresh clone, following only `README.md` setup steps and then `DEMO_SCRIPT.md`, works exactly as scripted, start to finish, with no undocumented manual steps.

**Phase 10 — Polish & documentation**
`README.md`: quickstart (`npm install && npm run setup && npm run dev`), architecture summary, env vars, how to run tests/benchmark, explicit "Demo / Not for Production Use" limitations section (local CA, local encryption key, no rate limiting, etc.). Full `npm test` and `npm run build` clean. Final pass over UI copy for anything that overstates security.

---

## 6. Explicit rejection/edge cases to handle (don't let these slide)

- Uploading a zero-byte or duplicate file.
- Signing a document that's already signed (should this create a new version, or block? — decide, document the decision in `PROGRESS.md`, and be consistent).
- Verifying a document with no signature yet (clear "not yet signed" state, not a crash).
- RBAC: a `VERIFIER` should not be able to sign; a `VIEWER` should not be able to upload or issue certificates; only `ADMIN` can revoke certificates.
- Concurrent verification requests should not corrupt the audit hash-chain (append safely).

---

## 7. What "research paper level" means for this build

The accompanying report claims specific, falsifiable things: that algorithm can be swapped without touching other layers, that revocation and expiry are correctly enforced, that tampering is reliably detected, and that performance across algorithms can be measured and compared. Your job is to make every one of those claims **actually true and actually tested** in running code — not to write code that merely looks like it does these things. When in doubt, favor a smaller feature set that is genuinely correct and tested over a larger feature set that isn't.

---

## Kickoff

Start with Phase 0. Before writing code, show me the exact `package.json` dependencies you intend to install and the Prisma schema for Phase 0–1, so I can sanity-check them against Section 3/4 above before you proceed.
