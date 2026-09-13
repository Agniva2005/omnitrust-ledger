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

---

## Phase 4a — RFC 5280 revocation reasons and signed CRLs

Phase 4 is split into three commits: 4a (revocation reasons and CRLs, this entry), 4b (a local RFC 3161 Time-Stamp Authority and signature time-stamping) and 4c (timestamp-aware verification). Verification still reads revocation from the certificate record until 4c.

### Research before implementation

- **RFC 5280** §5.3.1 (CRLReason codes) and §5.3.2 (invalidity date: "the date on which it is known or suspected that the private key was compromised or that the certificate otherwise became invalid").
- **ETSI EN 319 102-1** past signature validation: a revoked signing certificate with no proof of existence (POE) of the signature before the revocation is *indeterminate* (`REVOKED_NO_POE`), not failed; a signature time-stamp earlier than the revocation lets past validation succeed. **Limitation of this research:** the ETSI PDFs returned HTTP 403, and text extraction from the copies obtained was not possible in this environment, so the rule is taken from ETSI's published summaries and plugtest material rather than quoted clause text. Anything stricter than that rule is labelled below as OmniTrust policy.
- **RFC 3161** §2.4.2 and Appendix A, **RFC 5816** and **RFC 5035** for the time-stamp work in 4b, probed end to end before any code: a TimeStampResp built with the `@peculiar/asn1-*` classes, carrying SigningCertificateV2, passes `openssl ts -verify` (both response and bare token) and fails with "message imprint mismatch" when the time-stamped data changes.

### What changed

- **`lib/pki/revocation.ts`**: the RFC 5280 reasons this CA issues (not `certificateHold`/`removeFromCRL`), and `evaluateRevocation()`, the timestamp-aware policy `omnitrust-timestamp-aware-revocation/1` that 4c will apply:
  - not revoked → pass;
  - revoked, no proof of existence → **indeterminate** (per ETSI `REVOKED_NO_POE`);
  - non-compromise reasons → pass if the signature is proven to predate the revocation (or an earlier recorded invalidity date), otherwise invalid;
  - compromise reasons → pass only if proven to predate the recorded invalidity date; **with no invalidity date the compromise time is unknown and the signature is invalid** (OmniTrust policy, not an ETSI rule);
  - a proof counts as "before" only when its time **plus the time-stamp's stated accuracy** is strictly earlier; uncertainty never favours the signature.
- **Revocation takes structured input**: reason code, optional invalidity date (refused if later than the revocation or before the certificate's validity), optional comment. API validation and a reason picker in the UI, with a warning when a compromise is recorded without an invalidity date.
- **`lib/pki/crl.ts`**: every revocation makes the CA issue a new, numbered (`cRLNumber`), signed CRL containing reason codes and invalidity dates, stored as signed. `authenticateCrl()` accepts a list only if the local CA signed it and it is current; a forged, altered, lapsed or malformed list makes status **unavailable**, never "not revoked". `unspecified` is encoded by omitting the reason extension, as RFC 5280 asks.
- **Public exports** `GET /api/pki/crl` (DER, or `?format=pem`) and `GET /api/pki/ca`, so an external tool can check revocation without trusting the app.
- **Schema and migration** (`20260913093000_add_crl_timestamping_revocation_reasons`): reason code, invalidity date and comment on certificates; `RevocationList`; `TimestampAuthority` and signature time-stamp columns for 4b. A data step converts free-text reasons recorded before the migration into a comment plus `unspecified`.

### Bugs found and fixed during this phase

1. **CRLs used a PEM label OpenSSL refuses.** `@peculiar/x509` armours CRLs as `BEGIN CRL`; RFC 7468 and OpenSSL require `BEGIN X509 CRL`. OpenSSL reported "Could not find CRL". PEM export now uses the standard label.
2. **Revoked certificates appeared unrevoked to standard CRL consumers for about half of all serial numbers.** Found only over real HTTP, by reading a downloaded CRL with OpenSSL: the entry's serial printed as `-3D9387…` for a certificate whose serial is `C26C78…`. The certificate generator encodes a serial whose first byte has its top bit set as a positive INTEGER with a leading zero byte; the CRL generator encoded the same hex verbatim, producing a negative INTEGER that no longer matched. OpenSSL `verify -crl_check` would therefore accept such a revoked certificate. OmniTrust's own reader compared normalised hex text, which hid the mismatch, and the first OpenSSL test passed only because its random serial happened to have the top bit clear. Entries are now always positive INTEGERs byte-identical to the certificate's. The regression tests force a top-bit serial rather than hoping for one, compare the CRL entry's INTEGER bytes with the certificate's, and require OpenSSL to report that certificate revoked. The bug was caught before commit; the development database's affected CRL was superseded by a fresh one, which OpenSSL lists with the correct positive serial.
3. **The migration's data step had never touched data**: the suite only migrates empty databases, and the development database held no revoked certificates. `tests/prisma/migration-data.test.ts` runs that step's SQL, read from the migration file, against pre-migration-shaped rows, and checks its list of reason codes cannot drift from the code's.

### Verification

- `npm test`: **496 passed, 1 skipped** across 35 files (440 after Phase 3). The revocation policy truth table covers every reason with no proof, proof before, proof after, and a proof whose accuracy window straddles the event.
- OpenSSL CLI 3.2.4, in automated tests: `openssl crl -CAfile` reports `verify OK`, `Key Compromise`, `Invalidity Date` and `CRL Number`; `openssl verify -crl_check` rejects a revoked certificate (including one with a top-bit serial) with "certificate revoked" and accepts an active one.
- Over real HTTP against `npm run dev`: both downloads are served without a session with the right content types; OpenSSL verifies the downloaded CRL; the revoke endpoint rejects an unknown reason and a future invalidity date with 400; revoking with `keyCompromise` and an invalidity date issued a new CRL that OpenSSL reads with both fields. (An ML-DSA certificate cannot be checked with `openssl verify` on the 3.2.4 CLI, which cannot parse ML-DSA keys; the automated OpenSSL checks use ECDSA certificates.)
- `tsc --noEmit`, `npm run lint`, `npm run check:boundary`, `npm run build`: clean.
- Browser, signed in as `admin@demo`: each active certificate's Revoke button opens a form with the RFC 5280 reason picker and its description, an invalidity-date field and a comment; the previously revoked certificate shows `REVOKED` / `CERTIFICATE_REVOKED`; no console errors. (The form was not confirmed, to leave the seeded demo certificates intact; revocation itself was exercised over HTTP above.)

---

## Phase 4b — A local RFC 3161 Time-Stamp Authority

### What changed

- **CMS identifiers in provider metadata.** Each provider now declares how it appears in CMS SignedData: digest OID, signature OID and exact signature parameters. SHA-256 for RSA-PSS and ECDSA; SHA-512 for Ed25519 (RFC 8419: MUST) and ML-DSA-65 (RFC 9882). The RSASSA-PSS parameter DER was not written from memory: it was generated with `@peculiar/asn1-rsa` and found byte-identical to the parameters OpenSSL writes into its own RSA-PSS CMS signature. The time-stamp authority reads these instead of assuming ECDSA; Phase 5 will reuse them.
- **`lib/pki/cms.ts`**: CMS building blocks shared with Phase 5 — signed attributes in DER SET OF order (X.690 §11.6), the ESS signingCertificateV2 attribute (RFC 5035), signer identifiers, and a small DER walker with an arbitrary-size OBJECT IDENTIFIER decoder (see below). ASN.1 only; every digest and signature goes through the orchestrator.
- **`lib/pki/tsa.ts`**, the local Time-Stamp Authority:
  - its certificate is issued by the local CA with a **critical `id-kp-timeStamping`** as its only extended key usage (RFC 3161 §2.3), a policy OID under the unregistered ITU-T X.667 UUID arc (`2.25.<uuid>`), and a validity that cannot outlive the CA;
  - tokens are CMS SignedData over a TSTInfo with whole-second `genTime`, a stated one-second accuracy, content-type, signing-time, message-digest and signingCertificateV2 attributes, signed through the orchestrator;
  - `verifyTimestampToken()` returns VALID / INVALID / UNAVAILABLE, never collapsing them: structure, message imprint, issuing authority, signed attributes, signature, the authority certificate's chain, EKU and validity at `genTime`, and the authority's own revocation status under the Phase 4a policy (a token survives a later non-compromise revocation of the authority; a compromise without an invalidity date defeats it; unreadable revocation evidence makes it unavailable).
- **RFC 3161 over HTTP**: `POST /api/tsa` (DER `application/timestamp-query` in, `application/timestamp-reply` out), requiring a signed-in account, answering requests it cannot honour with RFC 3161 rejections (`badAlg`, `badDataFormat`, `unacceptedPolicy`, `unacceptedExtension`) rather than errors, echoing the nonce, and including the certificate only when `certReq` asks. `GET /api/pki/tsa` publishes the authority's certificate.
- **Every signature is time-stamped** over the SHA-256 of its signature value (RFC 3161 Appendix A), stored with the signature and audited as `TIMESTAMP_ISSUED`. An unavailable authority is audited as `TIMESTAMP_UNAVAILABLE` and does not block signing: the signature stays valid but cannot later be shown to predate a revocation. Using the token as proof of existence during document verification is Phase 4c.

### Library limitations found and worked around

1. **`@peculiar/asn1-ess` 2.9.4 cannot parse the DER form of ESSCertIDv2 that RFC 5035 requires.** When `hashAlgorithm` is the SHA-256 default, DER must omit it (X.690 §11.5), and the parser then fails with "Data does not match to ESSCertIDv2 ASN1 schema". Every valid token looked malformed to our own verifier while OpenSSL accepted it. The attribute is now read with `asn1js` against the RFC structure; encoding is unchanged. Unit tests cover the DER form, an explicit-SHA-256 form another implementation might send, and a non-SHA-256 hash, which is refused.
2. **`asn1js` renders an OBJECT IDENTIFIER arc beyond `Number.MAX_SAFE_INTEGER` as hex.** The TSA's 128-bit UUID policy arc therefore read back as `2.25.{0173…}`, which would have rejected any client naming the policy in its request as `unacceptedPolicy`. Policies are now read from the DER with a BigInt decoder (X.690 §8.19), tested against a real 128-bit arc and all three top-level arcs.
3. **A test mistake, caught by the verifier.** Two tests back-dated a token by a minute, before the freshly created authority's certificate existed; the verifier refused it as outside the certificate's validity, which is correct. The tests now wait out the token's accuracy window before revoking, and a new test asserts the back-dated case is refused.

### Verification

- `npm test`: **525 passed, 1 skipped** across 37 files (496 after Phase 4a).
- Automated OpenSSL CLI checks (3.2.4): `openssl ts -verify` accepts a stored token against the time-stamped data and rejects altered data; an `openssl ts -query` sent to the HTTP endpoint returns `Status: Granted` with the nonce echoed, and `openssl ts -verify -queryfile` reports `Verification: OK`.
- Over real HTTP against `npm run dev`: a document uploaded and signed through the API stored a 1117-byte token that verifies `VALID` in-app and `Verification: OK` in OpenSSL against the signature value, with a matching `TIMESTAMP_ISSUED` audit entry; `openssl ts -query` → `curl POST /api/tsa` → `openssl ts -verify -queryfile` reports `Verification: OK` with the full 128-bit policy OID; the endpoint refuses a cross-site POST (403) and an unauthenticated one (401).
- `tsc --noEmit`, `npm run lint`, `npm run check:boundary`: clean.

---

## Phase 4c — Timestamp-aware verification

### What changed

- **Verification uses trusted time instead of the server clock.** The signature's RFC 3161 token is verified over SHA-256 of the signature value; a VALID token's `genTime` (with its stated accuracy) is the proof of existence. The certificate's chain, profile and validity period are judged **at that time**, so a certificate that later expires does not invalidate a signature made while it was valid.
- **Revocation comes from the CA's signed CRL, not the database row.** Verification authenticates the current CRL (signature, issuer, currency) and applies `evaluateRevocation()` (policy `omnitrust-timestamp-aware-revocation/1`, Phase 4a). An unauthenticated or unreadable CRL makes revocation status UNAVAILABLE, never "not revoked".
- **Ten steps with stable ids** (`document`, `signature`, `certificate`, `timestamp`, `certificate-validity`, `revocation`, `public-key`, `recompute-hash`, `signature-verification`, `hash-comparison`) instead of matching on numbered labels. The time-stamp step is *optional*: a signature without a token (made before Phase 4b, or while the authority was unavailable) can still be VALID, but gets no benefit of the doubt when its certificate is later revoked or expires.
- **New reasons, kept in their verdict classes:** `TIMESTAMP_INVALID` (INVALID: a token that does not match this signature, or is corrupted); `REVOCATION_STATUS_UNAVAILABLE`, `REVOKED_NO_PROOF_OF_EXISTENCE` and `EXPIRED_NO_PROOF_OF_EXISTENCE` (UNVERIFIABLE, following ETSI EN 319 102-1's no-POE indications rather than declaring such signatures invalid).
- **The result explains itself**: an `explanation` sentence and a `trust` summary (server-clock signing time labelled as not evidence, trusted time and authority, the instant the certificate was judged at, whether it has since expired, the CRL revocation entry, the policy decision and policy id). The verify screen renders both. Audit entries for `DOCUMENT_VERIFIED` now record the trusted time and the revocation decision.
- **`validateCertificate()` gains `revocation: "check" | "skip"`** and reports where the evaluation instant falls in the validity window. Signing and the certificates page keep the default, so a currently revoked certificate still cannot sign and is still flagged; only verification skips it and decides revocation itself.

### Decisions recorded

- A revoked-then-verified sequence in the existing audit-trail test and the Phase 6 "revoked certificate" case now revoke for `keyCompromise` without an invalidity date. Under the new policy a `superseded` revocation after a time-stamped signature correctly leaves it VALID, so those tests' intent ("revocation defeats the signature") is expressed with the reason that has that meaning.
- The Phase 6 "expired certificate" case is now two cases: expired after a time-stamped signature → VALID; expired with no time-stamp → UNVERIFIABLE (`EXPIRED_NO_PROOF_OF_EXISTENCE`). Neither is `CERTIFICATE_EXPIRED`, which remains for a signature proven to have been made outside the validity period.
- Precedence: a hash mismatch outranks an invalid signature, which outranks an invalid time-stamp, because changing the bytes breaks the signature and changing the signature breaks its time-stamp; the earliest finding is the precise diagnosis.

### Verification

- `npm test`: **537 passed, 1 skipped** across 38 files (525 after Phase 4b). New `tests/verification/timestamp-aware.test.ts`, all with real signatures, real tokens and real CA-signed CRLs:
  - revoked for `affiliationChanged` after a time-stamped signature → VALID, `SIGNED_BEFORE_REVOCATION`, and the explanation says why;
  - `keyCompromise` with no invalidity date → INVALID, `COMPROMISE_TIME_UNKNOWN`;
  - `keyCompromise` with an invalidity date after the signature → VALID; before it → INVALID;
  - a genuine token obtained **after** the revocation does not rescue the signature (`SIGNED_AFTER_REVOCATION`);
  - a token from another signature, or a corrupted token → INVALID, `TIMESTAMP_INVALID`, while the signature and hash steps still pass;
  - no token, then revoked → UNVERIFIABLE, `REVOKED_NO_PROOF_OF_EXISTENCE`;
  - a tampered stored CRL → UNVERIFIABLE, `REVOCATION_STATUS_UNAVAILABLE`.
- Over real HTTP against `npm run dev`: two ECDSA certificates issued, two documents uploaded and signed through the API, both VALID with a trusted time; after revoking one for `affiliationChanged` and the other for `keyCompromise` (CRL #5), the first stays VALID (`SIGNED_BEFORE_REVOCATION`) and the second is INVALID (`COMPROMISE_TIME_UNKNOWN`, only the revocation step failing).
- Browser, `/documents/<id>/verify` for the `affiliationChanged` document: AUTHENTIC badge, explanation, the time-and-revocation panel (trusted time, authority, server clock marked as not evidence, CRL entry, policy decision) and all ten steps with the certificate sub-checks; no console errors. The page's "eight-step" description was stale and now describes ten steps.
- `tsc --noEmit`, `npm run lint`, `npm run check:boundary`, `npm run build`: clean.
