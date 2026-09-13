# OmniTrust Ledger — Security Audit (upgrade Phase 13)

Audit of the upgraded application after Phases 0–12. The method was reading every security-relevant module against its behaviour, and backing each conclusion with an automated test, a reproduction, or a stated limitation. Nothing below is claimed from comments or earlier documentation alone.

## Scope

- **Authentication and sessions:** `lib/auth/session.ts`, `lib/auth/rate-limit.ts`, login and logout routes.
- **Authorisation:** `lib/auth/rbac.ts`, and every `app/api` route handler (22 routes).
- **Request hardening:** `middleware.ts`, `lib/http/origin.ts`, `lib/http/security-headers.ts`, `next.config.ts`.
- **Key material and storage:** `lib/crypto/symmetric.ts`, `lib/documents/storage.ts`, `lib/documents/service.ts`, `lib/documents/export.ts`, and API responses.
- **PKI publication:** public CA, CRL and TSA certificate routes.
- **Logging:** every server-side `console.*` call.
- **Isolation of destructive tooling:** the Security Lab guard and sandbox.
- **Secrets at setup:** `scripts/setup.ts`, `.env.example`.

Integrity mechanisms (signatures, time-stamps, CMS, audit chain, checkpoints, anchoring) were verified in their own phases. They are summarised here only where they bear on an attack.

## Findings

Severity is relative to this demonstrator's stated purpose. "Fixed" means changed in code, covered by a test that failed before the fix, and committed.

| ID | Severity | Finding | Status |
| --- | --- | --- | --- |
| S1 | High (policy) | `POST /api/certificates` returned the new key pair's `encryptedPrivateKey` | **Fixed**, Phase 11 |
| S2 | Medium | Unauthenticated `GET` requests changed server state (TSA creation, CRL issuance) | **Fixed**, Phase 13 |
| S3 | Medium | A fresh installation's first time-stamp could predate its own authority certificate | **Fixed**, Phase 10 |
| S4 | Low | A not-yet-valid certificate was reported as `CERTIFICATE_EXPIRED` | **Fixed**, Phase 10 |
| S5 | Low | README limitations understate the implemented controls | **Fixed**, Phase 15 (README rewritten; guarded by `tests/ci/docs-claims.test.ts`) |
| L1–L10 | — | Accepted limitations of a local demonstrator | Documented below |

### S1 — Encrypted private key returned by the certificate issuance API

- **What:** the route passed the service's record, including `keyPair.encryptedPrivateKey`, straight into the JSON response.
- **Impact:** the AES-256-GCM ciphertext of the private key went to the issuer. It is unreadable without the local master key, but it breaks the rule that no API exposes private-key material, and it removes a layer of defence if that key file is ever obtained.
- **Fix:** the response reduces the key pair to `id`, `status` and `algorithm`.
- **Evidence:** `tests/api/routes.test.ts` scans every route response for `PRIVATE KEY`, `encryptedPrivateKey`, `passwordHash`, bcrypt hashes and stack traces. Five tests failed on this route before the fix.
- **Residual:** ciphertexts already delivered cannot be recalled; the demo master key was not rotated.

### S2 — State changes on unauthenticated GET

- **What:**
  - `GET /api/pki/tsa` called `ensureTimestampAuthority()`, which generates a key pair, has the CA sign a certificate, and writes the authority and an audit entry;
  - `GET /api/pki/crl` called `currentCrl()`, which makes the CA sign a new revocation list whenever the stored one has lapsed.
- **Impact:** GET is exempt from the cross-site origin check and needs no session, so anyone able to reach the server could make the CA or the key generator act. Each is bounded (one authority, one list per lapse), but unauthenticated requests must not cause signing or key generation.
- **Fix:** both routes are read-only. The TSA route serves an existing authority's certificate or returns 404. The CRL route serves the newest stored list, lapsed or not (its `nextUpdate`, also sent as `X-CRL-Next-Update`, tells a consumer it is stale), or returns 404. Issuance remains with revocation and authenticated verification.
- **Evidence:** `tests/pki/public-routes-readonly.test.ts` checks the 404 cases create no row and no `TSA_CREATED` or `CRL_ISSUED` audit entry, and that a lapsed list is served byte-for-byte without a new one being issued. The existing TSA and CRL tests had relied on the side effect, failed after the change, and now create the authority or list explicitly.

### S3 — First time-stamp could predate its authority

- **What:** `issueTimestampToken` took its time on entry, then created the authority. When that creation crossed a second boundary, the token's `genTime` fell before the authority certificate's `notBefore`. The verifier correctly rejected the token, so a valid signature could carry `TIMESTAMP_INVALID`.
- **Fix:** the time is taken after the authority exists.
- **Evidence:** `tests/pki/tsa-clock.test.ts` forces the boundary with a faked clock and failed on the old code with `genTime 18:12:23, notBefore 18:12:24`.

### S4 — Not-yet-valid reported as expired

- **What:** validation had one reason for both sides of the validity window.
- **Fix:** `CERTIFICATE_NOT_YET_VALID` is reported before `notBefore`, following RFC 5280's distinction.
- **Evidence:** `tests/verification/not-yet-valid.test.ts`.

### S5 — README limitations are stale

The "Limitations" section still says:
- there is no CRL: CA-signed CRLs exist since Phase 4a;
- there is no rate limiting or lockout: failed-login throttling exists since Phase 1;
- CSRF defence is SameSite only: Origin and Sec-Fetch-Site checks exist since Phase 1.

These are wrong in the cautious direction, but a document that misdescribes the controls is still wrong. It is left for the Phase 15 documentation rewrite, with every statement checked against code.

## Controls verified

| Control | How it was verified |
| --- | --- |
| Session JWT signature, issuer and expiry checked with the algorithm pinned to HS256; the role re-read from the database on every request | `tests/auth/protected-route.test.ts` (forged token, deleted user, demotion takes effect immediately) |
| Failed-login throttling per account (5 in 15 minutes) and per client, checked before the password | `tests/auth/rate-limit.test.ts`, `tests/auth/login-route.test.ts`, Security Lab `login-brute-force` |
| Account enumeration resistance: same result and comparable bcrypt cost for unknown user and wrong password | Code review of `authenticate()` (decoy hash) |
| Session cookie `httpOnly`, `SameSite=Lax`, 8-hour expiry | Code review of `sessionCookie()` |
| Cross-site state changes refused by Origin and Sec-Fetch-Site on `/api/*` | `tests/http/origin.test.ts`; 403 observed over HTTP in Phases 6–8 |
| CSP, `frame-ancestors 'none'`, `X-Frame-Options`, `nosniff`, `Referrer-Policy`, `Permissions-Policy`, COOP | `tests/http/security-headers.test.ts` |
| Role-based access on every route: 401 / 403 / 400 / 404 / 409 as appropriate | `tests/api/routes.test.ts`, plus the per-route tests; `tests/api/route-coverage.test.ts` requires a route-level test for all 22 routes |
| No key material, password hashes or stack traces in API responses | Response scan in `tests/api/routes.test.ts` |
| Unexpected errors return a generic message with a correlation id; logs keep only an error's first line | `tests/api/error-response.test.ts`; all five server `console` calls use `redactErrorForLog` |
| Private keys and document blobs encrypted at rest (AES-256-GCM); tampering detected by the tag | `tests/documents/storage.test.ts`, Security Lab `ciphertext-bitflip` |
| Storage path traversal refused | `absolutePath()` guard, `tests/documents/storage.test.ts` |
| Uploads: zero-byte, over-size (10 MB) and duplicate refused; exports served as attachments with `nosniff`, document bytes as `application/octet-stream` | `tests/api/routes.test.ts`, `tests/pki/cms-signature.test.ts` |
| Algorithm-specific code confined to `lib/crypto` | `npm run check:boundary`, `tests/crypto/boundary.test.ts` |
| Algorithm confusion and key substitution refused | `tests/verification/algorithm-confusion.test.ts`, Security Lab |
| Tampering with the audit log, including a consistent rewrite and truncation below a checkpoint, detected | `tests/audit/chain.test.ts`, `tests/audit/checkpoints.test.ts`, Security Lab |
| Destructive attack scenarios confined to disposable sandboxes | `tests/security-lab/security-lab.test.ts` (the guard refuses the development database; a full run leaves the calling database unchanged) |
| Secrets generated per installation (JWT secret, master key) and never committed | `scripts/setup.ts`; `.env` and `storage/` in `.gitignore` |

## Accepted limitations

These follow from building a local, single-process demonstrator and are stated rather than fixed.

- **L1** JWT sessions are stateless: logout clears the cookie, but a stolen token remains valid until its 8-hour expiry.
- **L2** Failed-login throttling is in memory, so it resets on restart and is per process. The per-client key trusts `X-Forwarded-For` and is a secondary control; the per-account limit is the one that cannot be sidestepped.
- **L3** CSP `script-src` includes `'unsafe-inline'`, because the Next.js App Router emits inline bootstrap scripts and a nonce pipeline is not implemented. React's escaping remains the primary XSS control.
- **L4** The session cookie's `secure` flag is set only in production builds.
- **L5** The master key is a local file, not an HSM or KMS. Its `0o600` file mode is not enforced on Windows. Anyone who can read the filesystem can read every private key.
- **L6** Authorisation is by role, not ownership: every role, including VIEWER, can read and export every document. Only adding versions is restricted to the owner or an admin.
- **L7** Request body size for `/api/*` relies on Next.js's `middlewareClientMaxBodySize` default of 10 MB, which applies because the middleware matches `/api/*`. This is framework behaviour, not verified by a test here.
- **L8** Anchoring sends transactions from the local node's public development account. That is acceptable only because the chain is local and holds no value.
- **L9** Dependency vulnerability scanning (`npm audit`) needs the npm registry and is not part of the offline CI. `npm run ci` checks that the installed tree matches `package.json`, not whether it has known advisories.
- **L10** The CA, TSA, audit signer and demo accounts are demo-grade and trusted by nothing outside this installation.

## Verification of this audit

- Every test file cited above was checked to exist.
- `npm test` after the S2 fix: **695 passed, 1 skipped** across 52 files. The new read-only route tests pass, and the TSA and CRL tests that had depended on the old side effect were changed to create the authority or list explicitly.
- The S2 fix is verified through the real route handlers in tests; it was not re-checked over HTTP against `npm run dev`.
- `tsc --noEmit`, `npm run lint`, `npm run check:boundary`, `npm run build`: clean.
