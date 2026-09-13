# OmniTrust Ledger — Upgrade Log

Phase-by-phase record of the upgrade from the audited baseline (`0831f70`) toward the
publication-quality system. Each entry states what changed, why, and the evidence that it
works. The audit that motivates these phases is
[`docs/audit/01-current-state-map.md`](audit/01-current-state-map.md); finding IDs (G1,
G5, …) refer to that document.

---

## Phase 0 — Forensic audit and feasibility baseline

Commit `ba6511d`.

- Every module under `app/`, `lib/`, `prisma/`, `scripts/` and `tests/` read and classified
  A–H. Thirteen security concerns recorded.
- Library feasibility established by probe before any design was chosen: native ML-DSA in
  Node 24.14 / OpenSSL 3.5.5; ML-DSA X.509 subject keys accepted by `@peculiar/x509` and
  chain-verified by OpenSSL 3.5; the system OpenSSL CLI (3.2.4) verifies CMS for RSA and
  ECDSA but not Ed25519 or ML-DSA.
- Dependencies added: `@peculiar/asn1-{schema,cms,x509,tsp}`, `viem`; dev-only `hardhat@2`,
  `solc`, `@noble/post-quantum`. The runtime `npm audit` is unchanged; new advisories are
  confined to Hardhat's dev tree.
- Baseline: 266 tests passing.

---

## Phase 1 — Architectural and security fixes

### What changed

| Finding | Fix | Evidence |
| --- | --- | --- |
| **G1** Storage I/O failure reported as `HASH_MISMATCH` | Verdicts are now `VALID` / `INVALID` / `UNVERIFIABLE` / `ERROR`, never collapsed. Each step carries `PASS` / `FAIL` / `UNAVAILABLE` / `SKIPPED`. New reasons: `STORAGE_UNAVAILABLE`, `CERTIFICATE_NOT_FOUND`, `UNSUPPORTED_ALGORITHM`, `INTERNAL_ERROR`. Positive evidence of a bad document outranks a verifier fault, which outranks missing evidence. `VALID` is refused unless every step passed. | `tests/verification/verdicts.test.ts`: a deleted blob is `UNVERIFIABLE` with no step marked `FAIL`; an unregistered algorithm is `UNVERIFIABLE`; a revoked certificate still yields `INVALID` when the blob is unreadable; a missing storage key is `ERROR` and does not leak its path; none of these advance the lifecycle to `VERIFIED`. |
| **G5** Chain validation ignored key usage and the issuer's CA profile | Validation now also requires: issuer `basicConstraints cA=TRUE`; the issuer CA certificate inside its own validity window at the evaluation instant; the leaf is an end entity (`cA` not TRUE); leaf `keyUsage` includes `digitalSignature`. Issuance refuses a certificate that would outlive its CA. | `tests/pki/chain-profile.test.ts`: certificates re-issued by the real CA key that differ only in the property under test, each with a control re-issue proving the helper itself preserves validity. |
| **G6** JWT role trusted for 8 hours | `getSession()` resolves the token against the user row on every request. The JWT algorithm is pinned to HS256. | `tests/auth/protected-route.test.ts`: a validly signed token for a non-existent user → 401; an unexpired admin token after demotion to VIEWER → 403. |
| **G7** No login throttling | Per-account limit (5 failures / 15 min, case-normalised) and a secondary per-forwarded-client limit (20 / 15 min). The limit is checked before bcrypt, so a locked account cannot confirm a correct password. `429` + `Retry-After`. New audit action `USER_LOGIN_THROTTLED`. | `tests/auth/login-route.test.ts` (lockout even with the correct password, reset on success, per-account isolation, case variants, password-spraying from one client); `tests/auth/rate-limit.test.ts` (window arithmetic with an injected clock). |
| **G8** No CSRF control beyond SameSite | `middleware.ts` refuses state-changing `/api/*` requests whose `Sec-Fetch-Site` is not same-origin or whose `Origin` names another host (including an opaque `null` origin or a different port). | `tests/http/origin.test.ts`; over real HTTP against `npm run dev`: forged `Origin` → 403, `Sec-Fetch-Site: cross-site` → 403, header-less client → reaches the route (401 for bad credentials); the real login form in a browser succeeds. |
| **G9** No security headers | CSP (`frame-ancestors 'none'`, `object-src 'none'`, `base-uri 'self'`, `form-action 'self'`), `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, COOP; `X-Powered-By` removed. `'unsafe-eval'` and `ws:` only in development. | `tests/http/security-headers.test.ts`; headers observed on a live response. No CSP violations in the browser console across login, document list and verification. |
| **G10** Authorisation failures surfaced as 409 | `AuthorizationError` (403) for issuing a certificate for another user, adding a version to another user's document, and signing with another user's certificate. | Assertions on the error class added to `certificates`, `service` and `signing` tests. |
| **G11** Signing not atomic | The signature row and lifecycle transition commit in one transaction. A unique-constraint race on the version maps to a 409 rather than a 500. | Existing signing tests unchanged and passing. |
| **G12** Whole error objects logged | `redactErrorForLog()` keeps the error name, code and only the first message line. Unexpected errors return a generic 500 with a correlation id. | `tests/api/error-response.test.ts`: an ORM-style multi-line error does not log the ciphertext on its later lines. |
| Audit (C) | `USER_LOGOUT` is now emitted. Signing out clears the cookie even if the audit write fails. | `tests/auth/logout-route.test.ts`. |
| Error mapping (H, found during this phase) | Lifecycle, key and not-signed errors previously fell through to a **500** because `errorResponse` only knew five classes. All status-bearing errors now extend `HttpError`. | `tests/api/error-response.test.ts` asserts 409 for `InvalidTransitionError`, `InvalidKeyTransitionError` and `DocumentNotSignedError`. |

### Found and fixed during this phase

- **Two pre-existing type errors in test files** (`tests/crypto/orchestrator.test.ts`, `tests/crypto/vectors.test.ts`), present since before this upgrade and invisible because neither Vitest nor `next build` type-checks test files. Found by running `tsc --noEmit` directly; fixed without changing what either test asserts at runtime. `tsc --noEmit` will be part of the local CI command.
- **A PKI-incorrect test expectation.** `tests/pki/validation.test.ts` validated a certificate at an instant *before its issuing CA existed* and expected `valid`. Under RFC 5280 path validation every certificate in the path must be valid at the evaluation time, so that result was wrong. The test now uses instants inside the CA's window; the before-the-CA case is covered as a chain failure.

### Deliberately not changed

- The CSP keeps `'unsafe-inline'` for scripts. The App Router emits inline bootstrap scripts, and removing it needs a per-request nonce pipeline. This will be stated as a limitation.
- Rate limiting is in-memory and per process, consistent with the single-process design already documented.
- The per-client limit keys on `X-Forwarded-For`, which is forgeable without a trusted proxy. It is secondary by design; the per-account limit cannot be sidestepped that way.

### Verification

- `npm test`: **319 passed** across 27 files (266 at baseline; none removed).
- `tsc --noEmit`: clean. `npm run lint`: clean. `npm run build`: clean, with middleware compiled for the edge runtime.
- Browser, against `npm run dev` with seeded data: sign-in through the real form; the RSA-signed agreement shows **AUTHENTIC** with every step `PASS`, including the four new certificate-profile checks; the pre-tampered invoice returns `INVALID` / `HASH_MISMATCH` with steps 1–6 passing and 7–8 failing.
