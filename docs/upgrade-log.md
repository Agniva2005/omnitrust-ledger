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

---

## Phase 2 — Provider abstraction, algorithm metadata, and a demonstrable agility claim

### What changed

- **Registry as the single source of algorithms.** `lib/crypto/registry.ts` holds `PROVIDERS`; the `Algorithm` type, `ALGORITHMS`, API validation and every UI list are derived from it. This corrects the audit finding (D/E) that "one provider file plus one registry line" undercounted: previously the `ALGORITHMS` tuple also had to change. The registry refuses a provider registered under an identifier it does not declare, and one whose issuer capability contradicts its certificate-signing parameters.
- **`lib/crypto/orchestrator.ts` is the layer's only public entry point.** It adds `lookup()` and `displayName()` for identifiers read from storage (never throwing), and `identifyPublicKey()`, which decides an algorithm from key material rather than from a stored label.
- **Structured algorithm metadata** (`AlgorithmMetadata`): family, classical/post-quantum class, standards, security level with its basis, quantum resistance, implementation library/backend/version, parameters, message processing, determinism, public key and signature sizes and encodings, serialisation, OIDs, interoperability (the OpenSSL command that independently verifies a signature), capabilities, security notes. Plain data, so the UI consumes it directly.
- **Providers sign messages, not digests.** The interface names what providers actually do; any hashing is the provider's own and is described in metadata. This is a prerequisite for CMS (Phase 5), where the signed message is the DER of the signed attributes.
- **Algorithm-agnostic PKI.** Certificate subjects are carried as SubjectPublicKeyInfo bytes (`subjectPublicKey()`), so no per-algorithm WebCrypto import is needed to certify a key. Probed before adoption: `@peculiar/x509` accepts an SPKI `PublicKey` for RSA, ECDSA, Ed25519 and ML-DSA-65 subjects, and OpenSSL 3.5 chain-verifies each with the SPKI byte-identical. WebCrypto parameters remain only for algorithms that act as a CA. The CA's algorithm moved to `lib/pki/policy.ts`, the single allowlisted place outside the crypto layer that names an algorithm.
- **Algorithm-consistency check (G4).** Verification step 5 now identifies the certificate's key from its material and requires it to agree with both the signature record and the certificate record. A disagreement is a new `INVALID` reason, `ALGORITHM_MISMATCH`, and no cryptographic operation is attempted across algorithms. Signing performs the same check before using a key.
- **Boundary checker extended to algorithm literals.** Import scanning cannot see `algorithm === "<id>"`. The checker now reads identifiers from the registry and flags any quoted occurrence outside `lib/crypto/` and the policy allowlist. On its first run it flagged its own header comment, which is how the rule was confirmed to work.
- **Everything outside the crypto layer that named an algorithm was made registry-driven:** the seed fixtures (one certificate and one signed sample per registered algorithm), the signature export script (OpenSSL command from metadata), and four UI pages that crashed on unknown algorithm identifiers (`as never` casts removed).

### Security finding: provider-level algorithm confusion (G14, pre-existing)

**The RSA-PSS and ECDSA providers did not check the type of the key they were given.** OpenSSL follows the key's own type and ignores options that do not apply, so:

| Provider | Given | Result before the fix |
| --- | --- | --- |
| RSA-PSS | an ECDSA private key | produced an ECDSA signature |
| RSA-PSS | a genuine ECDSA signature and the ECDSA public key | returned **valid** |
| ECDSA | an RSA **PKCS#1 v1.5** signature and the RSA public key | returned **valid** |

Consequence: a document signed under ECDSA whose signature and certificate rows were relabelled `RSA` verified as an authentic RSA-PSS signature. Once a post-quantum algorithm is registered, the same weakness would let a classical signature pass under a post-quantum label. The attacker needs database write access, and the signer identity was not forgeable (the certificate still had to chain to the CA), but the algorithm claim, which is central to this project's crypto-agility and post-quantum claims, was.

Found because a new orchestrator test, which chose its algorithm pair from the registry instead of hard-coding Ed25519, got a signature back instead of an error. Confirmed with plain `node:crypto` calls mirroring the providers exactly.

Fixed at two independent layers: each provider now refuses a key that is not of its own type and parameter set, for both signing and verification; and verification step 5 refuses any disagreement between the key material and the stored labels. Regression evidence:

- `tests/verification/algorithm-confusion.test.ts` recreates the relabelling attack end to end (now `INVALID` / `ALGORITHM_MISMATCH`, with step 7 skipped) and checks each provider directly.
- `tests/crypto/providers.test.ts` checks every ordered pair of registered algorithms: provider A refuses B's private key, and refuses B's genuine signature presented with B's own public key.

### Demonstrating agility rather than asserting it

`tests/crypto/agility.test.ts` performs the addition the claim describes. It extends the production registry with one entry, a **real ML-DSA-44 provider** (FIPS 204 on OpenSSL 3.5; not in the production registry, not a stub), and then runs the unmodified code end to end: the provider is discovered by every consumer; its keys carry the ML-DSA-44 OID and FIPS 204 sizes (1312-byte public key, 2420-byte signature); a certificate is issued and chain-validates; a document is signed and verifies `VALID`; tampering yields `HASH_MISMATCH`; pointing its signature at a classical certificate yields `ALGORITHM_MISMATCH`; and the boundary checker, now searching for the new identifier too, reports no violations. Nothing below the registry is mocked.

### Metadata as evidence

`tests/crypto/metadata.test.ts` checks every declared value against reality for every registered algorithm: the SPKI OID and public key size parsed from a generated key, the implementation version against the library actually loaded, serialisability, security-class consistency, the issuer capability. Where an `openssl` binary is on the PATH it runs the OpenSSL command each provider declares against a real signature, and requires the same command to reject a one-bit change to the message. On this machine (OpenSSL CLI 3.2.4) that passes for RSA-PSS, ECDSA P-256 and Ed25519.

### Found and fixed during this phase: seeding an existing database failed

Making the fixtures registry-driven changed sample filenames (for example `board-minutes-ecdsa.txt` became `board-minutes-ecdsa-p256.txt`). Running `npm run db:seed` against the existing development database then failed: the fixtures looked samples up by filename, found none, and tried to upload bytes the upload service correctly rejected as a duplicate. That would have broken the documented idempotency of `npm run setup` for anyone upgrading. Fixture seeding had no automated test, which is why the change slipped through.

Samples are now matched by content hash first, the same rule the upload service uses, then by filename. `tests/prisma/fixtures.test.ts` now covers the seed's promises: one signed sample per registered algorithm verifying `VALID` under that algorithm, the tampered sample `INVALID` / `HASH_MISMATCH`, the unsigned sample reported as not signed, an expired certificate, an intact audit chain, idempotent re-seeding, and re-seeding a database whose sample was stored under a legacy filename. The real development database that exposed the problem now seeds cleanly and reports its 34-entry audit chain intact.

### Verification

- `npm test`: **390 passed** across 31 files (319 after Phase 1).
- `tsc --noEmit`: clean. `npm run lint`: clean. `npm run check:boundary`: clean. `npm run build`: clean, with no import warnings.
- Over real HTTP against `npm run dev` after all changes: every page returned 200, and the three seeded signed documents verified `VALID` with step 5 reporting that each certificate's key matches its signature and certificate records; the tampered invoice returned `INVALID` / `HASH_MISMATCH`.
- Browser: the certificates page and the home page render algorithm metadata from the registry (security class, parameters, implementation and version).

---

## Phase 3 — ML-DSA-65, the fourth provider

### The agility claim, tested by doing it

ML-DSA-65 was added in its own commit, **`663e26b`**, so the change is its own evidence:

```
$ git show --stat 663e26b
 lib/crypto/providers/mldsa.ts | 138 ++++++++++++++++++++++++++++++++++++++++++
 lib/crypto/registry.ts        |   2 +
 2 files changed, 140 insertions(+)
```

One new provider file and a two-line registry change (its import and its entry). No document management, PKI, verification, storage, API route, UI page, seed fixture or script changed. With only those two files added, the existing test suite, which iterates the registry rather than naming algorithms, exercised ML-DSA-65 through key generation, metadata conformance, certificate issuance and chain validation, signing, verification, tamper detection, provider-level algorithm-confusion refusal across every ordered pair, and seeding.

### Implementation

- ML-DSA from **OpenSSL 3.5.5 through `node:crypto`** (native code, same backend as RSA-PSS and ECDSA). Pure mode, empty context string.
- Metadata states what was observed by probe before it was written, not what was assumed:
  - signing is **hedged (randomised)**: two signatures over the same message differ, both verify;
  - FIPS 204 sizes: **1952-byte** public key, **3309-byte** signature;
  - SubjectPublicKeyInfo OID `2.16.840.1.101.3.4.3.18` as found in OpenSSL-generated keys;
  - NIST post-quantum security category 3 (FIPS 204); X.509 per RFC 9881, CMS per RFC 9882.
- Refuses keys of any other type, **including the other ML-DSA parameter sets** (tested with ML-DSA-44 and ML-DSA-87 keys), applying the lesson of finding G14.
- Capabilities: can be certified (`x509Subject`); cannot act as this installation's CA (`x509Issuer` false), since certificate signing uses WebCrypto and Node marks ML-DSA there as experimental.

### Independent verification

The OpenSSL command-line tool supports ML-DSA only from version 3.5; the CLI on the development machine is 3.2.4. So ML-DSA declares no CLI command, and the metadata test that runs each provider's declared command is skipped for it and reported as skipped. Independent verification comes from a second implementation instead. `tests/crypto/mldsa-interop.test.ts` checks OpenSSL against **`@noble/post-quantum`**, an audited pure-JavaScript FIPS 204 implementation:

- key generation from the **same 32-byte seed** (exported from OpenSSL as a JWK `AKP` key) yields a **byte-identical public key** in both implementations;
- noble verifies signatures made by the OpenSSL-backed provider and rejects them over an altered message;
- the provider verifies signatures made by noble and rejects them over an altered message;
- the provider accepts a noble key it never generated once wrapped in SubjectPublicKeyInfo, and the orchestrator identifies that key as ML-DSA-65.

### Verification

- `npm test`: **440 passed, 1 skipped** across 32 files. The skipped test is the OpenSSL-CLI interoperability check for ML-DSA-65, which cannot run for the reason above.
- `tsc --noEmit`, `npm run check:boundary`, `npm run build`: clean.
- `npm run db:seed` on the existing development database issued an ML-DSA-65 certificate and signed `service-contract-ml-dsa-65.txt` without any fixture change; audit chain intact (38 entries).
- Over real HTTP against `npm run dev`: the seeded ML-DSA document verifies `VALID` (3309-byte signature; step 5 confirms an ML-DSA-65 key matching both records); `POST /api/certificates` with `ML_DSA_65` returns 201 with an `ACTIVE` certificate; an unregistered `ML_DSA_87` is rejected with 400, the allowed list in the error coming from the registry.
- Browser: the certificates page offers "ML-DSA-65 (post-quantum)" in the issue form and lists both ML-DSA certificates as valid; the home page shows it with its security class and signature size. The dev server logged no errors.
