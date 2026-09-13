# OmniTrust Ledger — Current State Map (pre-upgrade audit)

Audit of commit `0831f70`, performed by reading every module under `app/`, `lib/`,
`prisma/`, `scripts/` and `tests/` and checking behaviour against the code rather than
against comments or earlier documentation. Baseline at audit time: **266 tests passing,
`npm run build` clean, `npm run lint` clean.**

Classification key:

| Code | Meaning |
| --- | --- |
| A | Fully implemented and tested |
| B | Implemented but insufficiently tested |
| C | Partially implemented |
| D | Architecturally present but not demonstrated |
| E | Claimed but not actually implemented (or overstated) |
| F | Missing |
| G | Security concern |
| H | Technical debt |

---

## A — Fully implemented and tested

| Feature | Evidence in code | Tests |
| --- | --- | --- |
| Password auth (bcrypt cost 12), JWT HS256 httpOnly cookie, timing-equalised unknown-account path | `lib/auth/session.ts` | `tests/auth/session.test.ts`, `login-route.test.ts` |
| Capability-based RBAC (ADMIN / SIGNER / VERIFIER / VIEWER) | `lib/auth/rbac.ts` | `tests/auth/rbac.test.ts`, `protected-route.test.ts` |
| Document upload, SHA-256, zero-byte / duplicate / oversize rejection, versioning | `lib/documents/service.ts` | `tests/documents/service.test.ts` |
| AES-256-GCM blob encryption at rest, fresh IV per write, path containment | `lib/crypto/symmetric.ts`, `lib/documents/storage.ts` | `tests/documents/storage.test.ts` |
| Document lifecycle state machine (Figure 4) | `lib/documents/lifecycle.ts` | `tests/documents/lifecycle.test.ts` |
| RSA-PSS 3072, ECDSA P-256, Ed25519 providers | `lib/crypto/providers/*` | `providers.test.ts`, `vectors.test.ts` (RFC 8032 vector, OpenSSL ↔ @noble cross-checks, @noble/curves cross-check) |
| Provider registry / orchestrator | `lib/crypto/orchestrator.ts` | `tests/crypto/orchestrator.test.ts` |
| Import-based crypto boundary checker, itself tested with probe files | `scripts/check-crypto-boundary.ts` | `tests/crypto/boundary.test.ts` |
| Self-signed local root CA; X.509 issuance for all three algorithms | `lib/pki/ca.ts`, `lib/pki/certificates.ts` | `tests/pki/certificates.test.ts` |
| Certificate validation: issuer, CA signature, validity window, revoked flag, DB-vs-certificate consistency | `lib/pki/validation.ts` | `tests/pki/validation.test.ts` |
| Signing with preconditions (own cert, cert validates, not already signed, stored bytes still match) | `lib/documents/signing.ts` | `tests/documents/signing.test.ts` |
| Eight-step verification with structured per-step result; five required failure modes without mocked crypto | `lib/documents/verification.ts` | `tests/verification/workflow.test.ts` |
| Hash-chained audit log, tamper localisation (edit / delete / re-attribution / recomputed-hash), concurrent appends | `lib/audit/log.ts`, `lib/audit/integrity.ts` | `tests/audit/chain.test.ts`, `trail.test.ts` |

No fabricated cryptography was found. Every signature in the running system is produced
and verified by `node:crypto` (OpenSSL) or `@noble/ed25519`; every hash is real.

## B — Implemented but insufficiently tested

| Feature | Gap |
| --- | --- |
| API routes for documents, signing, verification, certificates, revocation, audit verification | Only `/api/auth/login` and `/api/admin/probe` have route-level tests; the rest are exercised only through their service functions and manual HTTP checks. |
| `scripts/benchmark.ts` | Single run, no standard deviation or confidence interval, 5 key generations, p95 by floor index. The only test checks output shape, and only if the file exists. |
| `scripts/export-signature.ts` | OpenSSL verification was performed by hand (recorded in PROGRESS.md); there is no automated test. |
| Seed fixtures (`prisma/fixtures.ts`) | Verified by manual clean-state runs, not by an automated test. |
| All UI pages | No automated UI checks; verified manually in a browser. |

## C — Partially implemented

| Feature | What exists | What is missing |
| --- | --- | --- |
| Key lifecycle (Figure 7) | States and a transition table (`lib/pki/keys.ts`) | No rotate or retire operation, no API, no UI, no "rotation due" policy. Only ACTIVE and REVOKED are ever reached. |
| Certificate lifecycle (Figure 6) | ACTIVE / EXPIRED / REVOKED | No renewal. EXPIRED is swept only as a side effect of listing certificates. |
| Revocation | Status column, timestamp, free-text reason | No RFC 5280 reason codes, no `invalidityDate`, no CRL. |
| Document lifecycle ARCHIVED / REVOKED | Declared states | No operation, route or UI reaches them. |
| Dashboard | Shows the actor's capabilities | No system statistics. |
| Audit coverage | Login, failed login, upload, version, sign, verify, certificate issue/revoke, key lifecycle | `USER_LOGOUT` is declared but the logout route never emits it. |

## D — Architecturally present but not demonstrated

| Claim | Reality |
| --- | --- |
| "Adding a fourth algorithm is one provider file plus one registry line" | Never exercised with a real algorithm. The only test registers an in-test object. The claim also **undercounts**: the `ALGORITHMS` tuple in `lib/crypto/types.ts` must change as well. |
| Algorithm-agnostic layers above `lib/crypto` | True for imports, but two files outside `lib/crypto` carry per-algorithm knowledge the import checker cannot see: `scripts/export-signature.ts` (`OPENSSL_COMMANDS` keyed by algorithm) and `prisma/fixtures.ts` (a hard-coded three-algorithm sample mapping). |
| Signing time | `Signature.signedAt` is the database server clock at insert. Nothing binds it to the signature or authenticates it. |

## E — Claimed but not implemented, or overstated

| Where | Statement | Finding |
| --- | --- | --- |
| `lib/crypto/orchestrator.ts`, home page, README | One provider file plus one registry line | Overstated by one edit (the `ALGORITHMS` tuple). Corrected by the agility work in this upgrade. |
| `AUDIT_ACTIONS` | `USER_LOGOUT` | Declared, never emitted. |

No claim of fabricated or mocked cryptography was found in the UI or the documentation.

## F — Missing relative to the upgrade brief

ML-DSA; a structured algorithm metadata model (family, security class, OIDs, key and
signature sizes); trusted timestamping; timestamp-aware revocation; CRL publication; RFC
5280 reason codes; an intermediate CA; CMS / PKCS#7 detached signatures; blockchain
anchoring with Merkle batching; a Security Lab; a key rotation workflow; a certificate
explorer; statistically rigorous benchmarks; a local CI command; a threat model;
distinct UNVERIFIABLE and ERROR verification verdicts; rate limiting; security headers.

## G — Security concerns

| ID | Concern | Location | Consequence |
| --- | --- | --- | --- |
| G1 | **A storage I/O failure is reported as tampering.** A missing or unreadable blob (ENOENT, EACCES) lands in the same branch as an AES-GCM tag failure and yields `HASH_MISMATCH`. There is no UNVERIFIABLE state. | `lib/documents/verification.ts` step 6 | A false accusation of tampering when the system simply cannot check. The verdict set collapses "cannot verify" into "invalid". |
| G2 | **Revocation invalidates every past signature**, regardless of when the signature was made or why the certificate was revoked. | `lib/pki/validation.ts` | A certificate retired for `affiliationChanged` retroactively breaks every document its holder signed while employed. |
| G3 | Signing time is an unauthenticated server timestamp. | `Signature.signedAt` | No proof of existence before a revocation, so historical validity (G2) cannot be established even in principle. |
| G4 | **No algorithm-consistency check** between the signature record, the certificate record and the algorithm of the public key actually inside the certificate. | `lib/documents/verification.ts` | Algorithm confusion is currently stopped only because a provider happens to reject a foreign key type. That is a side effect, not a control. |
| G5 | Chain validation checks the issuer name and CA signature, but **not** the leaf's key usage (`digitalSignature`), the issuer's `basicConstraints cA=TRUE`, or the CA certificate's own validity window. | `lib/pki/validation.ts` | A certificate issued without signing key usage, or under an expired CA, would be accepted for signatures. |
| G6 | The JWT's role is trusted for its full 8-hour life. A deleted or demoted user keeps their privileges. | `lib/auth/session.ts` `getSession()` | Privilege persists after revocation of the account or role. |
| G7 | No login rate limiting or lockout. | `app/api/auth/login/route.ts` | Unbounded online password guessing. |
| G8 | No CSRF token or Origin check on state-changing routes; `SameSite=Lax` is the only defence. | all `POST` routes | Relies entirely on browser SameSite behaviour. |
| G9 | No security headers (CSP, frame-ancestors, `nosniff`, Referrer-Policy). | `next.config.ts` | Clickjacking and content-sniffing defences are absent. |
| G10 | Authorisation failures surface as HTTP 409 in three places. | `issueCertificate`, `addDocumentVersion`, `signDocument` (foreign certificate) | Wrong semantics (not a bypass): clients and audits cannot distinguish "forbidden" from "conflict". |
| G11 | Signing is not atomic: the signature row, the lifecycle update and the audit append are separate writes. | `lib/documents/signing.ts` | A failure mid-way can leave a signature with no lifecycle transition or audit record. |
| G12 | Unhandled errors are logged as whole objects. Prisma errors can echo query arguments. | `lib/api.ts` `errorResponse()` | Risk of sensitive values in server logs. |
| G13 | The signature format is bespoke: RSA and ECDSA compute `Sign(SHA-256(SHA-256(document)))` and store raw bytes with no signed attributes. | `lib/documents/signing.ts` | Interoperable only via a hand-written export script, and nothing binds the signing certificate or signing time into the signed data. |

## H — Technical debt

- `orchestrator.describe(x as never)` casts on database strings in four UI pages: an unknown algorithm value crashes the page instead of rendering "unsupported".
- The boundary checker is import-based only; it cannot detect algorithm branching on string literals (see D).
- Audit append serialisation is in-process only.
- `package.json#prisma` configuration emits a Prisma 7 deprecation warning on every CLI call.
- The benchmark computes no dispersion statistics.
- Navigation is a flat top bar; there is no certificate detail view, key view or document timeline.

---

## Upgrade plan derived from this audit

The brief's phase order is followed. Items above map onto phases as follows:

| Phase | Addresses |
| --- | --- |
| 1 — Architectural and security fixes | G1 (verdict taxonomy), G5, G6, G7, G8, G9, G10, G11, G12 |
| 2 — Provider abstraction and metadata | D (agility claim), G4, H (`as never` casts, literal branching) |
| 3 — ML-DSA | F |
| 4 — Trusted timestamping and timestamp-aware revocation | G2, G3, C (revocation), F (CRL, reason codes) |
| 5 — CMS / PKCS#7 detached signatures | G13 |
| 6 — Audit chain strengthening | C (audit coverage), H (serialisation) |
| 7 — Blockchain anchoring and Merkle proofs | F |
| 8 — Security Lab | F |
| 9 — UI/UX redesign | C (dashboard, key lifecycle UI), H (navigation) |
| 10 — Benchmarks | B (benchmark rigour) |
| 11–14 — Tests, local CI, security audit, regression | B (route-level tests) |
| 15 — Documentation and evidence | — |

## Library feasibility established during the audit

These probes were run before committing to a design:

- **Node 24.14.0 bundles OpenSSL 3.5.5, which implements ML-DSA-44/65/87 natively** (`generateKeyPair('ml-dsa-65')`, `sign(null, …)`, standard PKCS#8 / SPKI encodings). ML-DSA can therefore use the same OpenSSL backend as RSA and ECDSA. `@noble/post-quantum` is added as an independent cross-check for tests only.
- **ML-DSA X.509 certificates are feasible.** `@peculiar/x509` embeds an ML-DSA-65 SubjectPublicKeyInfo (OID `2.16.840.1.101.3.4.3.18`, RFC 9881) in a certificate signed by an ECDSA issuer, and OpenSSL 3.5 parses it, reports the key as `ml-dsa-65`, verifies it against the issuer, and verifies an ML-DSA signature made with the key extracted from it.
- **The system OpenSSL CLI is 3.2.4.** It verifies CMS detached signatures for RSA (PKCS#1 v1.5 and PSS) and ECDSA, and provides `openssl ts`. It **cannot** process Ed25519 CMS (`CMS_add1_signer: unsupported signature algorithm`) and cannot parse ML-DSA keys. External-tool verification is therefore bounded: RSA and ECDSA via the OpenSSL CLI; Ed25519 and ML-DSA via an independent implementation in tests rather than a CLI.
- Standards consulted for CMS and timestamping: RFC 5652 (CMS), RFC 8419 (EdDSA in CMS: digest MUST be SHA-512), RFC 9882 (ML-DSA in CMS: SHA-512 MUST be supported), RFC 4056 (RSASSA-PSS in CMS), RFC 5753 (ECDSA in CMS), RFC 5035 (signingCertificateV2), RFC 3161 (time-stamp protocol; Appendix A signature time-stamp attribute; critical `id-kp-timeStamping`), RFC 5280 (CRLReason codes, `invalidityDate`).
