# PROGRESS

Build log for OmniTrust Ledger, tracked against the phases in `CLAUDE.md` Section 5.

| Phase | Status | Notes |
| --- | --- | --- |
| 0 — Scaffold | Done | Next 15 + TS + Tailwind 3 + Prisma/SQLite + Vitest; Section 3 folder map created with stubs |
| 1 — Auth & RBAC | Done | bcrypt + JWT httpOnly cookie, capability-based RBAC, login page; 52 tests |
| 2 — Document management | Done | Upload, real SHA-256, AES-256-GCM blobs at rest, versioning, Figure 4 state machine; 84 tests |
| 3 — Crypto orchestration | Done | RSA-PSS / ECDSA P-256 / Ed25519 providers + registry, boundary check enforced in CI; 146 tests |
| 4 — PKI layer | Done | Self-signed local root CA, X.509 issuance under all three algorithms, validation, revocation; 197 tests |
| 5 — Signing in document flow | Done | Signing via certificate picker; signatures verified outside the app with the OpenSSL CLI; 217 tests |
| 6 — Verification workflow | Done | Exact 8-step Figure 8 sequence, structured result, step checklist UI; all five failure cases tested; 243 tests |
| 7 — Audit & monitoring | Next | — |
| 8 — Benchmarking | Not started | — |
| 9 — Seed data & demo script | Not started | — |
| 10 — Polish & documentation | Not started | — |

## Phase 0 — Scaffold (complete)

Done:

- `git init`, `.gitignore` (excludes `.env`, `*.db`, `storage/`, generated benchmark JSON).
- `package.json` with the dependency set approved at kickoff. Version pins and why: Next `15.5.25` (spec allows 14+; Next 16 defaults are unnecessary risk), Prisma `6.19.3` (npm's `latest` tag for the `prisma` CLI currently points at an 8.0.0 **release candidate**; 6.19.3 is the last stable 6.x and matches the `prisma-client-js` generator shape), Tailwind `3.4.x` (shadcn/ui compatibility without the v4 CSS-first migration), Vitest `3.2.x`.
- Next.js App Router scaffold: `app/layout.tsx`, `app/page.tsx` (architecture/build-status placeholder), `app/globals.css`, `tailwind.config.ts`, `postcss.config.mjs`, `next.config.ts`, `tsconfig.json` with `@/*` path alias.
- Section 3 folder map created; every `/lib` module is a stub carrying its layer name and the phase it gets implemented in.
- `prisma/schema.prisma` — datasource + generator only, no models yet (Phase 0 DoD). `prisma/seed.ts` stub.
- `lib/db.ts` — PrismaClient singleton (guards against hot-reload connection churn in dev).
- `vitest.config.ts` + `tests/scaffold.test.ts` (19 tests: asserts the Section 3 folder map exists and that `.env.example` documents every variable the app reads while `.env` stays ignored).
- `scripts/setup.ts` behind `npm run setup`: generates `.env` from `.env.example` with a fresh random `JWT_SECRET`, creates `storage/{documents,keys}`, generates `storage/keys/master.key` (32 random bytes, mode 0600), then `prisma generate` → `prisma migrate deploy` → seed. Idempotent: never overwrites an existing `.env` or master key.
- `PROGRESS.md` (this file).

Definition of Done — verified:

- `npm run dev` serves the home page: `GET / → 200`, page renders.
- `npm test` runs: 19 passed.
- `npx prisma migrate dev` succeeds against the empty schema ("Already in sync").
- `npm run build` compiles clean, types valid.

## Phase 1 — Auth & RBAC (complete)

Done:

- `User` model + first real migration (`20260912185615_add_user`).
- `lib/auth/rbac.ts` — `Role` union, `isRole`/`assertRole`, a role-to-capability map, `can()`, `requireRole()`, `requireCapability()`, and `AuthenticationError` (401) / `AuthorizationError` (403).
- `lib/auth/session.ts` — bcrypt hashing (cost 12), `authenticate()`, JWT issue/verify via `jose` (HS256, 8h, issuer-checked), httpOnly `SameSite=Lax` cookie helpers, `getSession()`.
- `lib/api.ts` — error-to-status mapping shared by every route; unknown errors become a generic 500 so internals never leak to the client.
- Routes: `POST /api/auth/login`, `POST /api/auth/logout`, `GET /api/auth/me`, and `GET /api/admin/probe` (an ADMIN-only diagnostic endpoint that exists for the RBAC test).
- Login page with demo-account quick-fill buttons, `(app)` route group whose layout redirects unauthenticated visitors to `/login`, dashboard showing the actor's resolved capabilities, nav + sign-out.
- shadcn/ui primitives vendored: button, input, label, card, badge.
- `prisma/fixtures.ts` (shared by the seed script and tests) seeds four demo users.
- Tests: 52 passing across `tests/auth/{rbac,session,login-route,protected-route}.test.ts`.

Definition of Done — verified:

- Seeded users can log in. Verified over real HTTP against `npm run dev`: `POST /api/auth/login` → 200 with `#HttpOnly` cookie; `GET /api/auth/me` → 200 with the right role and capability list.
- A protected route rejects wrong roles. `GET /api/admin/probe` → 200 as ADMIN, 403 as SIGNER/VERIFIER/VIEWER, 401 unauthenticated or with a forged cookie. `/dashboard` unauthenticated → 307 to `/login`.
- `npm test` 52 passed, `npm run build` clean.

Notable during this phase:

- **`zod.string().email()` had to go.** It rejects `signer@demo` because there is no TLD, which would have made the Section 5 Phase 9 demo accounts unusable. Since the spec fixes those names, the login field is validated as a length-bounded opaque identifier (resolved by exact match) rather than as an RFC email address. Noted in the route.
- **Test database harness.** `tests/global-setup.ts` deletes `prisma/test.db` and runs `prisma migrate deploy` against a fresh file, so the suite never touches `prisma/dev.db`. It deliberately does *not* use `prisma db push --force-reset`: Prisma 6 guards that command against AI agents, and applying the committed migrations forward is both non-destructive and a better test, since it proves the migration history builds a working schema.
- **Prisma CLI is invoked through `node` directly** (`lib/prisma-cli.ts`), not `npx`. Spawning the `npx.cmd` shim without a shell fails with `EINVAL` on Windows, and enabling the shell would concatenate arguments instead of escaping them.

## Phase 2 — Document management (complete)

Done:

- `Document` / `DocumentVersion` schema + migration (`20260912...add_documents`), with `User.documents` back-relation and indexes on owner and current hash.
- `lib/documents/lifecycle.ts` — the Figure 4 state machine as an explicit transition table with `canTransition` / `assertTransition` / `assertPath` / `nextStates` and two terminal states.
- `lib/documents/storage.ts` — Secure Storage layer. Writes blobs to `storage/documents/<documentId>/v<n>.bin`, encrypted; makes no crypto decisions itself, only calls the Cryptographic layer. Includes path-containment checking so a malformed `storagePath` can never resolve outside the storage root.
- `lib/documents/service.ts` — upload, duplicate/zero-byte/size validation, versioning, `recomputeVersionHash()` (which is verification step 6, deliberately uncached).
- `lib/crypto/hash.ts` and `lib/crypto/symmetric.ts` — see the deviation note below.
- Routes: `GET`/`POST /api/documents`, `GET /api/documents/[id]`, `POST /api/documents/[id]/versions`.
- UI: documents list (real hashes and lifecycle state), upload form, document detail showing current state, the legal next states straight from the state machine, and per-version hashes.
- Tests: 84 passing. New: `tests/documents/{lifecycle,storage,service}.test.ts`.

Definition of Done — verified over real HTTP against `npm run dev`:

- Uploaded `agreement.txt`; the app computed `e8a7cb0baa17015c0b2005b237be493c411888bb68609fbf657dd334553985b3`, which is byte-identical to what `sha256sum` reports for the same file outside the app.
- The document appears in the list UI (checked in a browser, signed in as `signer@demo`) with that hash and status `HASHED`.
- Section 6 edge cases: zero-byte upload → 400; duplicate bytes → 409 naming the existing document.
- On-disk blob is 110 bytes for an 82-byte input (12-byte IV + 16-byte GCM tag + ciphertext) and contains none of the plaintext.
- `npm test` 84 passed, `npm run build` clean.

Deliberate deviation from phase ordering:

- **`lib/crypto/hash.ts` and `lib/crypto/symmetric.ts` were created in Phase 2, not Phase 3.** Phase 2 requires SHA-256 on upload and Section 3 requires document blobs encrypted at rest, while Section 2 rule 2 forbids cryptographic primitives outside `/lib/crypto/`. Putting a `createHash` or `createCipheriv` call in `lib/documents/` would have violated the hard rule; adding these two files early satisfies both. The orchestrator and the three signature providers remain Phase 3 work.

## Phase 3 — Cryptographic Orchestration Layer (complete)

Done:

- `lib/crypto/types.ts` — `Algorithm` union (`RSA` | `ECDSA_P256` | `ED25519`), the `SignatureProvider` interface (`sign`, `verify`, `generateKeyPair` plus display metadata and WebCrypto parameters), and PEM helpers.
- `lib/crypto/providers/rsa.ts` — RSASSA-PSS, 3072-bit modulus, SHA-256, digest-length salt, via `node:crypto`.
- `lib/crypto/providers/ecdsa.ts` — ECDSA over NIST P-256 with SHA-256, DER-encoded, via `node:crypto`.
- `lib/crypto/providers/eddsa.ts` — Ed25519 via `@noble/ed25519` (+ `@noble/hashes` for the required SHA-512), with RFC 8410 PKCS#8/SPKI wrappers so the rest of the app only ever handles PEM.
- `lib/crypto/orchestrator.ts` — registry keyed by algorithm, `providerFor()`, and `sign`/`verify`/`generateKeyPair`/`describe`/`webCryptoParams`. **Adding a fourth algorithm is one new provider file plus one line in `REGISTRY`.** Nothing else in the codebase references a specific algorithm.
- `scripts/check-crypto-boundary.ts` — scans `app/ lib/ components/ prisma/ scripts/`, excluding `lib/crypto/`, and reports any `@noble/*` import, any `@peculiar/x509` import outside `lib/{crypto,pki}`, and any `node:crypto` signature/cipher/digest symbol (including via a namespace import). Runnable as `npm run check:boundary` and enforced inside `npm test`.
- Tests: 146 passing overall; 62 in `tests/crypto/`.

Definition of Done — verified:

- `npx vitest run tests/crypto` passes for all three algorithms.
- The boundary check reports zero violations — **and the checker is itself tested**: four cases write a probe file into `lib/documents/` containing a forbidden import and assert it gets flagged, so the guard cannot silently pass by being broken.
- `npm test` 146 passed, `npm run build` clean.

Independent correctness, not just round-trips (Phase 3 DoD wording):

- **Ed25519 is checked against the RFC 8032 section 7.1 Test 1 vector** — secret key `9d61b1…7f60`, public key `d75a98…511a`, empty message, signature `e55643…100b`. Before embedding the vector I confirmed it two ways: our provider reproduces it, and OpenSSL (`node:crypto`) independently produces the byte-identical signature from the same key. The suite also asserts our RFC 8410 PEM encoding is byte-identical to OpenSSL's own export, that OpenSSL verifies what `@noble` signs, and that `@noble` verifies what OpenSSL signs.
- **ECDSA P-256 is cross-validated against `@noble/curves`** (added as a *dev*-dependency for exactly this): signatures our OpenSSL-backed provider produces verify under `@noble`, signatures `@noble` produces verify under ours, and generated public keys are asserted to lie on the curve.
- **RSA-PSS has no second implementation available here, and the tests say so rather than overclaiming.** It is checked structurally (3072-bit modulus, exponent 65537, signature exactly 384 bytes) and through WebCrypto as a different API surface, including a check that the signature is genuinely PSS — verifying it as PKCS#1 v1.5 fails — and that a wrong salt length is rejected.
- Signature shapes are asserted per spec: Ed25519 exactly 64 bytes, RSA exactly 384, ECDSA a well-formed DER `SEQUENCE` of two `INTEGER`s between 68 and 72 bytes with the declared length matching the actual.
- Behavioural properties that distinguish the schemes are asserted too: RSA-PSS and ECDSA are randomised (two signatures over the same digest differ, both verify), Ed25519 is deterministic (byte-identical).
- Every provider is tested to reject a flipped digest bit, a flipped signature bit, a truncated signature, and the wrong public key; and a cross-algorithm matrix asserts no signature ever verifies under a different algorithm.

Design notes:

- **What gets signed is the 32-byte SHA-256 digest of the document**, as Phase 5 specifies ("orchestrator signs the current document hash"). The RSA and ECDSA providers then apply their own SHA-256 to that digest because `node:crypto` offers no "sign a pre-computed digest" API without hand-rolling DigestInfo padding — which Section 2 rule 1 forbids. So the effective construction is `Sign(SHA-256(SHA-256(document)))` for RSA/ECDSA, and Ed25519 signs the digest directly (hashing with SHA-512 internally per RFC 8032). The interface stays uniform: every provider is handed the same 32 bytes.
- **Providers expose WebCrypto parameters** (`keyImport` / `signing`) so the Phase 4 PKI layer can build and sign X.509 certificates without naming an algorithm itself, which is what keeps the boundary rule satisfiable rather than merely aspirational.
- `orchestrator.sign`/`verify`/`generateKeyPair` are `async` so an unregistered algorithm *rejects* rather than throwing synchronously — one error path for callers. A test caught this.

## Phase 4 — PKI Layer (complete)

Done:

- Schema + migration (`20260912192444_add_pki`): `CertificateAuthority`, `KeyPair`, `Certificate`, with back-relations on `User`.
- `lib/crypto/keys.ts` — WebCrypto key import and the `@peculiar/x509` crypto-provider wiring. This lives in `lib/crypto` because `node:crypto`'s `webcrypto`/`subtle` are primitives the boundary rule keeps out of other layers; the PKI layer calls these helpers and never names an algorithm.
- `lib/pki/ca.ts` — the self-signed local root CA: created once, idempotently, 10-year validity, `basicConstraints CA:true`, `keyUsage keyCertSign|cRLSign`, private key encrypted at rest.
- `lib/pki/certificates.ts` — issuance (key pair from the orchestrator → X.509 signed by the CA → `KeyPair` + `Certificate` rows), revocation, listing, `publicKeyPemFromCertificate()` (verification step 5) and `signableCertificates()` for the Phase 5 picker.
- `lib/pki/validation.ts` — chain / validity / revocation checks returning a structured result with a per-step list, plus `markExpiredCertificates()` for the Figure 6 `ACTIVE -> EXPIRED` transition.
- `lib/pki/keys.ts` — the Figure 7 key lifecycle (`generated -> active -> rotated -> revoked -> retired`, NIST SP 800-57) and the Figure 6 certificate lifecycle as explicit transition tables.
- Routes: `GET`/`POST /api/certificates`, `POST /api/certificates/[id]/revoke`.
- UI: certificates page showing the root CA, an issue form driven by `orchestrator.describeAll()` (so a fourth algorithm would appear without touching the page), live per-certificate validation status, and a two-step revoke button visible only to ADMIN.
- Seed now creates the root CA and one certificate per algorithm for `signer@demo`.
- Tests: 197 passing; 51 in `tests/pki/`.

Definition of Done — verified over real HTTP:

- Certificates issued under all three algorithms for `signer@demo`: `ED25519`, `ECDSA_P256`, `RSA`, each `ACTIVE` with a unique 16-byte serial.
- Revoked one as ADMIN → its validation flips to `CERTIFICATE_REVOKED` on the certificates page while the other two still report `valid`. The underlying `KeyPair` moves to `REVOKED` in the same transaction.
- Section 6 RBAC over HTTP: a VIEWER gets 403 on both issue and revoke; a SIGNER cannot issue for another user; only ADMIN can revoke.
- `npm test` 197 passed, `npm run build` clean.

Notable during this phase:

- **All three algorithms work through `@peculiar/x509` against a single ECDSA root CA**, verified by probe before building: certificate creation, chain verification, and the subject public key round-tripping back to a byte-identical PEM. Issued certificate sizes differ usefully for the Phase 8 benchmark table (RSA 713 bytes, ECDSA 382, Ed25519 334). `node-forge` was therefore never needed as the Section 1 fallback.
- **The root CA is ECDSA P-256, not RSA.** The CA's algorithm is independent of its subjects' by design, and a P-256 issuer keeps the size differences between issued certificates attributable to the subject key rather than swamped by a 384-byte RSA signature on every certificate.
- **`CertificateAuthority.algorithm` is an addition to the Section 4 field list.** Without it the CA's signing algorithm would have to be hard-coded somewhere, which Section 2 rule 2 forbids; storing it means the CA is resolved through the orchestrator like everything else.
- **Validation cross-checks the database against the certificate bytes.** If a row's serial number or expiry disagrees with the certificate it stores, that is reported as `CERTIFICATE_CHAIN_INVALID` — otherwise editing the DB row could silently change a validity window. Tested.
- Reason precedence is documented and tested: a certificate that is both expired and revoked reports `CERTIFICATE_EXPIRED`, because Section 3 step 4 lists validity before revocation. Both failures still appear in the step list.

## Phase 5 — Signing wired into the document flow (complete)

Done:

- `Signature` schema + migration (`20260912193302_add_signatures`), unique per document version.
- `lib/documents/signing.ts` — `signDocument()` composes three layers and does no crypto itself: the PKI layer supplies the certificate and decrypts the key, the orchestrator produces the signature, the lifecycle validates the transition. The payload is the raw 32 bytes of the current version's SHA-256.
- Preconditions enforced before signing: the capability, the certificate belongs to the actor, the certificate *validates* (so a revoked or expired certificate cannot be used to sign), the version is not already signed, and — an integrity precondition — the stored bytes still hash to the recorded hash, so a signature never attests to content that was never there.
- Route: `POST /api/documents/[id]/sign`.
- UI: a sign panel on the document detail page whose picker lists certificates, not algorithms (the certificate implies both algorithm and key), plus a signatures table showing algorithm, signature size, certificate serial, signer and timestamp. Lifecycle card shows the current state and the legal next states.
- `scripts/export-signature.ts` (`npm run export:signature -- <documentId|filename>`) exports the plaintext, the signed digest, the raw signature, the certificate and the public key, then prints the exact OpenSSL command for that algorithm.
- Tests: 217 passing; 20 in `tests/documents/signing.test.ts`.

Definition of Done — verified, and verified from outside the app:

- Signed three documents under all three algorithms over real HTTP: signature sizes 384 (RSA-PSS 3072), 70 (ECDSA P-256 DER) and 64 (Ed25519) bytes; all three documents ended at lifecycle state `STORED`.
- **The hash recomputed outside the app matches**: `sha256sum` on the original file equals the `signedHash` the API reported, for all three.
- **The signatures verify outside the app**, with the OpenSSL 3.2.4 CLI and no application code in the loop:
  - RSA: `openssl dgst -sha256 -verify ... -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1` → `Verified OK`
  - ECDSA P-256: `openssl dgst -sha256 -verify ...` → `Verified OK`
  - Ed25519: `openssl pkeyutl -verify -pubin -rawin ...` → `Signature Verified Successfully`
  The public key in each case was extracted from the stored certificate with `openssl x509 -pubkey -noout`, so this exercises the certificate too, not just the raw key.
- A test asserts the signature is over the raw 32 hash bytes and *not* over the 64-character hex string — the hex text does not verify.
- `npm test` 217 passed, `npm run build` clean.

## Phase 6 — Verification workflow (complete)

Done:

- `lib/documents/verification.ts` — the eight Figure 8 steps in the spec's exact order, returning the `VerificationResult` shape the spec declares (`outcome`, optional `reason`, `steps[]`). Every step records its own result even after an earlier one fails, so the checklist shows *which* check went wrong rather than stopping at the first problem. Step 4's sub-checks from the PKI layer are nested underneath it.
- Reason precedence, documented in the code and tested: certificate problems outrank content problems, and `HASH_MISMATCH` outranks `SIGNATURE_INVALID` (when the bytes change the signature necessarily fails too, and "the document was altered" is the more precise diagnosis).
- A document with no signature raises `DocumentNotSignedError` rather than being reported as `INVALID` — it is neither authentic nor invalid (Section 6). The route maps it to a 409 with `notSigned: true` and the UI renders a "Not yet signed" card.
- On `AUTHENTIC`, the document advances `STORED -> VERIFIED` (Figure 4).
- Route: `POST /api/documents/[id]/verify`. UI: `/documents/[id]/verify` with a step checklist, a large AUTHENTIC/INVALID badge, the machine-readable reason code, and a plain-English explanation of what that reason means.
- Tests: 243 passing overall; 26 in `tests/verification/workflow.test.ts`.

Definition of Done — all five required failure cases, none of them mocking crypto:

| Required case | Test outcome |
| --- | --- |
| Flip one byte in a stored document blob | `HASH_MISMATCH` (step 6 fails: AES-GCM tag) |
| Verify with an expired certificate | `CERTIFICATE_EXPIRED`, with steps 7 and 8 still passing — the cryptography is fine, only the window has closed |
| Verify after revoking the signing certificate | `AUTHENTIC` before revocation, `CERTIFICATE_REVOKED` after, with the revocation reason in the step detail |
| Corrupt the signature bytes | `SIGNATURE_INVALID` for all three algorithms, with step 8 still passing — the document was not touched |
| Substitute a different algorithm's public key | `SIGNATURE_INVALID` for all three algorithms, and no crash even when the substituted key is structurally unusable |

Plus the extra case promised in decision 9: replacing the blob with **validly re-encrypted different plaintext** (an attacker who also holds the storage key). The AES-GCM tag passes, step 6 succeeds, and **step 8's hash comparison is what catches it** — so the hash-comparison path is genuinely exercised, not merely asserted.

Also verified: all eight numbered steps execute in order 1-8; verification is repeatable; the public key comes from the certificate and not the `KeyPair` row (corrupting that row does not affect the outcome); a VERIFIER can verify and a VIEWER cannot.

Confirmed in a real browser, not only in tests: signed in and ran verification on a tampered document, and the UI rendered the full checklist with `INVALID` / `HASH_MISMATCH`, steps 1-5 passing and step 6 explaining that the bytes on disk are not the bytes that were written.

**Bug found and fixed during this phase:** `tailwind.config.ts` used `require("tailwindcss-animate")` inside an ES module, which Node 24 rejects with `ReferenceError: require is not defined` when compiling CSS against a cold `.next`. Every page failed to compile in dev until it was changed to a normal `import`. This would have broken the first `npm run dev` on a clean clone, which is exactly the Phase 9 acceptance path. (Found because `npm run build` and `npm run dev` were sharing `.next` and corrupted it — worth avoiding: stop the dev server before building.)

## Phase 7 — Audit & monitoring (complete)

Done:

- `AuditLogEntry` schema + migration (`20260912195010_add_audit_log`) with a unique `seq`.
- `lib/audit/log.ts` — `entryHash = SHA256(prevHash + canonical serialisation of the entry's own fields)`, exactly as Section 4 specifies, chained from a genesis hash of 32 zero bytes. Canonical serialisation fixes field order explicitly (rather than trusting object key order), escapes the separator so two different entries can never serialise identically, and sorts metadata keys.
- `lib/audit/integrity.ts` — walks the chain recomputing every hash, reporting `SEQUENCE_GAP`, `PREV_HASH_MISMATCH` and `ENTRY_HASH_MISMATCH` with the sequence number and a human-readable detail. The next entry is expected to link to what the previous one *recomputes* to, not to the hash it happens to store, so one edit really does break the chain from that point onwards.
- Audit entries emitted for: login, failed login (identifier only, never the password), upload, new version, sign, verify (both outcomes with the reason and the list of failed steps), certificate issue, certificate revoke, and key lifecycle transitions in both directions.
- Routes: `POST /api/audit/verify`. UI: `/audit` with the entry table and a "Verify log integrity" button that reports the first break, its sequence number and what specifically went wrong.
- Tests: 263 passing; 20 in `tests/audit/`.

Definition of Done — verified:

- A realistic demo sequence (issue → upload → sign → verify → tamper → verify → revoke → verify) produces a coherent trail: every required action type appears, all three verifications are recorded with their outcomes and reasons (`AUTHENTIC`, `HASH_MISMATCH`, `CERTIFICATE_REVOKED`), and actions are attributed to the user who performed them.
- The integrity check passes on the untouched log and **identifies exactly where the chain breaks** when a row is edited directly in the database: the altered entry's sequence number, its id, and `ENTRY_HASH_MISMATCH`.
- Four distinct tamper shapes are covered: altered metadata, altered action/target, an entry re-attributed to a *different real user* (so the foreign key still holds and only the chain gives it away), a deleted entry (`SEQUENCE_GAP`), and a "smart" tamper where the attacker recomputes `entryHash` but cannot fix the next entry's link (`PREV_HASH_MISMATCH` at the following sequence).
- Section 6 concurrency: 25 simultaneous appends leave the chain valid with contiguous sequence numbers 1-25. Appends are serialised in-process and the unique `seq` constraint is the backstop, with a losing writer retrying against the new tail.
- A test asserts the log never contains a password, a bcrypt hash, or a private key.
- `npm test` 263 passed, `npm run build` clean.

## Decisions log

Decisions that Section 6 or the spec asks to be recorded, plus judgement calls made where the spec left room.

1. **No Prisma enums.** Prisma does not support `enum` on the SQLite provider, so every role / status / algorithm column is `String`. The allowed values live as TypeScript unions in the module that owns the concept (`lib/auth/rbac.ts`, `lib/crypto/types.ts`, `lib/documents/lifecycle.ts`, `lib/pki/keys.ts`) and are validated before every write. This is also the more Postgres-portable choice Section 1 asks for. Tradeoff: the database will not reject a bad value on its own, so the `/lib` validators are the single enforcement point and are unit-tested as such.
2. **`bcryptjs`, not `bcrypt`.** Same algorithm, pure JS, no native toolchain needed — matters on Windows and for a clean-clone demo.
3. **`jose` for the session JWT.** No transitive dependencies, and works in the edge runtime if route protection moves to middleware.
4. **`zod` added** beyond the spec's dependency list, for API-boundary input validation only. No crypto or business logic in it.
5. **shadcn/ui components are vendored by hand** rather than via the interactive `shadcn init`, which is how shadcn is designed to be consumed (copy-in, not a runtime dependency). Keeps the clean-clone path free of an interactive CLI step.
6. **Tests run serially** (`fileParallelism: false`). Test suites share one SQLite file; serial execution avoids write-lock contention. Revisit if the suite gets slow.
7. **Section 6: signing an already-signed document is blocked, not auto-versioned.** Attempting to sign a version that already has a signature returns 409 with a message pointing at "upload a new version". Reason: a `DocumentVersion` is the unit that has exactly one signed hash, so allowing several signatures per version would make verification step 8 ("compare recomputed hash vs. the hash that was actually signed") ambiguous about *which* signature is authoritative. To sign again, upload a new version — the document goes `VERSIONED -> HASHED` and is signable once more. Phase 5 Phase DoD signs across the three algorithms on *different* documents, so nothing in the demo needs multi-signature support.
8. **Section 6: duplicate uploads are rejected per owner, not globally.** Identical bytes from the same owner → 409 naming the existing document; identical bytes from a different owner are allowed, since two users legitimately holding the same contract is not an error.
9. **Document blobs are encrypted at rest, which changes how blob tampering surfaces.** Section 3 requires encrypted blobs, so a flipped byte in a stored blob fails the AES-256-GCM authentication tag before any hash comparison can run. That failure is surfaced as `HASH_MISMATCH` (the Phase 6 reason code) with a detail line explaining that the stored bytes are not the bytes that were written — it is still genuine, byte-level tamper evidence, just detected one layer earlier. Phase 6 therefore tests tampering *twice*: a raw byte flip (caught by the GCM tag) and a validly re-encrypted substitution of different plaintext (caught by the hash comparison itself), so the hash-comparison path is exercised for real and not merely asserted.
10. **Known dev-time advisories, accepted.** `npm audit` reports 7 findings, all in build/dev tooling and none in the app's request path: `@vitest/mocker` (test runner), `deepmerge-ts` via `@prisma/config` (Prisma CLI), and `postcss` 8.4.31 as a nested dependency of Next 15's build pipeline (the top-level `postcss` resolves to a patched 8.5.28). Every offered fix is a major upgrade that would break the pins above. To be restated in the README limitations section in Phase 10.

## Next: Phase 8 — Benchmarking

- `scripts/benchmark.ts`: N sign+verify cycles per algorithm across a couple of payload sizes, timed with `process.hrtime.bigint()`, reporting mean/median/p95 plus signature and certificate sizes.
- Results written to a JSON file, rendered on a `/benchmarks` page read from that file.
- Label the machine and environment, and state that absolute numbers are environment-dependent — the cross-algorithm comparison is the point.
