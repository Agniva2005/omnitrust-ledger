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

---

## Phase 5 — Detached CMS / PKCS#7 signatures with external verification

### Design decision: a second signature, made in the same action

The stored signature is over the raw 32 bytes of the version's SHA-256. A CMS SignedData with signed attributes cannot contain that value: RFC 5652 section 5.4 requires the signature to be computed over the DER of the signed attributes, which carry the message digest. Re-encoding the existing value as CMS would therefore produce a file no standard verifier accepts, and inventing an "OmniTrust CMS" would not be CMS.

So the signing action now produces **two signatures by the same key over the same document bytes**, and says so in the schema, the signing module and the UI:

1. the stored signature, which the in-app verification workflow checks (unchanged); and
2. a **detached CMS SignedData** (`Signature.cmsSignature`) for export:
   - content type `id-data`, no embedded content;
   - signed attributes: content-type, signing-time, message-digest of the document bytes under the provider's declared CMS digest (SHA-256 for RSA-PSS and ECDSA; SHA-512 for Ed25519 per RFC 8419 and ML-DSA per RFC 9882), and ESS signingCertificateV2;
   - the signer's and the CA's certificates, so a verifier needs only the trust anchor;
   - an RFC 3161 time-stamp over the SignerInfo's own signature value as the `id-aa-signatureTimeStampToken` unsigned attribute (RFC 3161 Appendix A). This is structurally a CAdES-style time-stamped signature; **no CAdES profile conformance is claimed**.

Signatures made before this phase have no CMS signature; exporting one returns 409 with that explanation rather than fabricating one.

### What changed

- **`lib/pki/cms-signature.ts`**: `createDetachedSignature()` and `verifyDetachedSignature()`. The verifier returns VALID / INVALID / UNAVAILABLE and checks structure, that the signer's certificate is carried and matches the signer identifier, that the algorithm identified from the key matches the digest OID, signature OID and exact parameters its provider declares, the content-type, message-digest and signingCertificateV2 attributes, the signature, the chain to the local CA with the digitalSignature key usage, and any signature time-stamp. Revocation over time remains the verification workflow's job.
- **Provider metadata** declares `interoperability.opensslCms` (true for RSA-PSS and ECDSA, false for Ed25519 and ML-DSA), so the UI and export script show an OpenSSL command only where it works.
- **Export**: `GET /api/documents/:id/export?part=cms|content|certificate[&version=n]` (any signed-in reader; `DOCUMENT_EXPORTED` audited). Served as attachments with `nosniff`; document bytes as `application/octet-stream` so uploaded content never renders inline; filenames sanitised for `Content-Disposition`. The document page lists the three downloads per signature and shows the external `openssl cms -verify` command with the honest scope of that check. `npm run export:signature` also writes `signature.p7s` and `ca.pem` and prints the command.
- **Migration** `20260913150000_add_cms_detached_signature` adds the nullable `cmsSignature` column.

### External evidence

- **RSA-PSS and ECDSA**: `openssl cms -verify -binary -inform DER -in … -content … -CAfile ca.pem` reports `CMS Verification successful`, and fails with `content verify error` when one byte is appended to the document. Checked with **both** OpenSSL CLIs present on the machine, **3.4.0** (MSYS2) and **3.2.4** (Git for Windows), in the automated tests and on files downloaded over HTTP. `openssl ts -verify` accepts the embedded signature time-stamp over the signature value.
- **Ed25519**: neither OpenSSL CLI can process Ed25519 CMS at all. OpenSSL 3.4.0 refuses to *create* one of its own (`CMS_add1_signer: no default digest`, reproduced with an OpenSSL-generated Ed25519 key and certificate) and refuses to verify ours with `Explicit digest not allowed with EdDSA operations`; 3.2.4 fails the same way. This is a limitation of the tool, not evidence about the encoding. Independent check instead: the signed-attribute bytes are extracted from the file with `asn1js` (not the app's encoder), confirmed to contain the SHA-512 of the document, and verified with **`node:crypto`'s Ed25519** (OpenSSL's implementation; the app signs Ed25519 with `@noble/ed25519`); a one-byte change is rejected.
- **ML-DSA-65**: neither CLI can build a chain with an ML-DSA certificate (support arrives in OpenSSL 3.5). Independent check: the same extracted bytes verified with **`@noble/post-quantum`** (the app signs ML-DSA with OpenSSL through `node:crypto`); a one-byte change is rejected.
- `openssl asn1parse` parses the export for all four algorithms.

### Correction to earlier entries

Two OpenSSL CLIs are installed: PowerShell resolves `openssl` to **MSYS2's 3.4.0**, Git Bash to **Git's 3.2.4**. The test suite spawns whichever is first on `PATH`, and it has been run from PowerShell, so the automated OpenSSL checks recorded above as "OpenSSL CLI 3.2.4" (Phases 4a and 4b) actually ran against **3.4.0**. To make the record true for both, the CRL, TSA, CMS and provider-metadata test files were re-run with Git's 3.2.4 first on `PATH`: **95 passed, 1 skipped** (the ML-DSA CLI command, as before). The Phase 0 audit's statement that "the system OpenSSL CLI is 3.2.4" describes only the Git Bash environment.

### Bugs found during this phase

1. **A failed migration was recorded as applied.** A stale `shadow-migrate.db` left at the repository root made `prisma migrate diff` fail, the empty output was written as the migration, and `migrate deploy` recorded that empty migration as applied to the development database, so the column did not exist. Found by checking the table's columns rather than trusting the "applied" message. The migration row was removed, the SQL regenerated after deleting the stale shadow database, the migration re-applied, and the column confirmed with `pragma_table_info`.
2. **A weak test, fixed before commit.** The first version of the "swapped signer certificate" test only removed a certificate and issued one it never used. It now checks both a removed signer certificate and one replaced by a different real certificate.

### Verification

- `npm test`: **570 passed, 1 skipped** across 39 files (537 after Phase 4c). New `tests/pki/cms-signature.test.ts` (33 tests):
  - every algorithm's CMS signature verifies in-app with a valid signature time-stamp, uses its provider's identifiers, is detached and carries two certificates; re-encoding is byte-identical, so rejections come from the tampering;
  - altered document bytes (message digest), a flipped signature bit, a removed or replaced signer certificate, another document's signature, and non-CMS bytes are all INVALID;
  - the OpenSSL, `node:crypto` and `@noble/post-quantum` checks above, plus a test that every registered algorithm has at least one independent check;
  - export: bytes, content types, audit entries, 409 for a signature without CMS, 404 for an unsigned version, filename sanitising, and the route's 401 / 400 / 404 / 200 responses with `attachment` and `nosniff`.
- Over real HTTP against `npm run dev`: for all four algorithms, a document uploaded and signed through the API and exported as a `viewer`; the CMS files verify with both OpenSSL CLIs for RSA-PSS and ECDSA and fail on altered content; unauthenticated export 401; unknown part 400.
- Browser: the document page shows the CMS / Document / Certificate links and the external-verification card; no console errors.
- `tsc --noEmit`, `npm run lint`, `npm run check:boundary`, `npm run build`: clean.

---

## Phase 6 — Audit chain strengthening: signed checkpoints and coverage

### The gap

The hash chain detects an edited row only while the stored hashes are left alone. Anyone who can write to the database can change an entry and then recompute and rewrite every later `prevHash` and `entryHash`, or delete entries from the end. In both cases `verifyAuditChain()` still reports the chain intact. The new tests demonstrate both cases passing the chain check before showing them caught.

### What changed

- **Signed, time-stamped checkpoints** (`lib/pki/audit-checkpoints.ts`, models `AuditSigner` and `AuditCheckpoint`):
  - a dedicated **audit-signer certificate** issued by the local CA (digitalSignature and nonRepudiation, not a CA), so the CA and TSA keys never sign audit data;
  - a checkpoint signs a line-based payload `omnitrust-audit-checkpoint/1` with the covered sequence number, the **hash of that entry derived from the genesis hash** (ignoring every stored hash), the previous checkpoint's hash and the creation time; the signature value is RFC 3161 time-stamped;
  - checkpoints form their own chain; `prevCheckpointHash` is unique, so two checkpoints cannot fork from one parent;
  - only an ADMIN can create one (`audit:checkpoint`), and **never over a log that does not verify**, since that would certify the tampering.
- **`verifyAuditLog()`** walks the chain (`walkAuditChain()` now also derives each entry's hash from genesis), then checks every checkpoint: its own hash, its link to the previous checkpoint, its signature under a certificate that chains to the CA, its time-stamp, and that the log still derives the committed hash at the committed sequence. New findings: `LOG_REWRITTEN`, `LOG_TRUNCATED`, `CHECKPOINT_ALTERED`, `CHECKPOINT_CHAIN_BROKEN`, `CHECKPOINT_SIGNATURE_INVALID`, `CHECKPOINT_TIMESTAMP_INVALID`. The result states how many entries after the latest checkpoint rest on the chain alone and **returns its limitations with every verification**.
- **Audit coverage**: the CA, Time-Stamp Authority and audit signer are audited when created (`CA_CREATED`, `TSA_CREATED`, `AUDIT_SIGNER_CREATED`); tokens issued through the RFC 3161 HTTP endpoint are audited with the requesting user; every integrity check is audited with who ran it and what it found (`AUDIT_VERIFIED`); checkpoint creation is audited.
- **Append retries are narrowed**: only the `seq` unique-constraint conflict is retried; any other failure (for example a foreign-key violation) is raised immediately instead of being retried five times.
- **API and UI**: `POST /api/audit/checkpoints` (ADMIN), `GET /api/audit/checkpoints` (any reader), `POST /api/audit/verify` returning the reconciled result. The audit page adds a "Create signed checkpoint" button for admins, a checkpoint table, separate chain and checkpoint badges, the explanation, per-checkpoint problems, and a "What this check cannot detect" disclosure.
- **Migration** `20260913170000_add_audit_checkpoints`. This time the SQL was generated after deleting stale shadow databases and was refused unless it created both tables.

### Stated limits (tested as limits)

1. Entries after the latest checkpoint are protected only by the hash chain; a consistent rewrite of them passes.
2. Deleting the newest checkpoint together with the entries it covers cannot be detected from this database alone. Phase 7 anchors checkpoints outside it.
3. The signer's private key is encrypted with the same local master key as every other key, so someone holding both the database and that key file can forge checkpoints.

### Verification

- `npm test`: **589 passed, 1 skipped** across 40 files (570 after Phase 5). New `tests/audit/checkpoints.test.ts` (19 tests):
  - a checkpoint commits to the verified head, is time-stamped, links to its predecessor, and is recorded after itself;
  - only admins create checkpoints; a broken log is refused; concurrent attempts never fork the checkpoint chain;
  - **a consistent rewrite** of a checkpointed entry and **deletion of entries below the latest checkpoint** both pass `verifyAuditChain()` and are caught as `LOG_REWRITTEN` and `LOG_TRUNCATED`;
  - an altered checkpoint (with and without its own hash recomputed), a flipped signature bit, a swapped time-stamp, and a checkpoint removed from the middle are each caught with the specific finding;
  - the three limits above, asserted to behave as documented;
  - a checkpoint signature verifies with the OpenSSL CLI (`openssl dgst -sha256 -verify`, "Verified OK") and fails on an altered payload;
  - coverage: CA, TSA and signer creation audited; `AUDIT_VERIFIED` records the actor and result; viewers are refused; a foreign-key failure is raised at once (`P2003`).
- Over real HTTP against `npm run dev` (non-destructive; the demo log was not tampered with):
  - verifying 115 entries before any checkpoint reports the chain intact and says a rewrite would not be detectable;
  - checkpoint creation is refused for a verifier (403), cross-site (403) and without a session (401), and succeeds for the admin (201, time-stamped, covering sequence 117);
  - a viewer can list checkpoints (200) but not verify (403);
  - verification then reports 1 agreeing checkpoint with a trusted time and one later entry on the chain alone.
- Browser, `/audit` as admin: "LOG VERIFIED", "chain intact", "1 checkpoint agree", the explanation, the checkpoint row (RFC 3161, admin@demo), and the new audit entries; no console errors.
- `tsc --noEmit`, `npm run lint`, `npm run check:boundary`, `npm run build`: clean.

---

## Phase 7 — Blockchain anchoring with Merkle batching (local chain)

### Scope, stated first

- Only **32-byte commitments** are anchored, batched into a Merkle tree; **only the root and the leaf count go on chain**. No document, no personal data, no key, no value and no token is ever sent to the chain.
- An anchor shows that a commitment was part of a tree whose root was recorded **in a given block of that chain instance**. It does **not** identify anyone: who signed is established by the PKI, not by the chain.
- The chain is a **local, in-memory Hardhat development node**. Restarting it discards every anchor; verification then reports UNAVAILABLE, never a pass and never a fabricated failure.
- Transactions come from the node's **public development account**; the app holds no chain key. A public chain would need real key custody, which is not implemented.

### Feasibility probes (before any project code)

- `solc` 0.8.37 (solcjs) compiles the contract under Node 24 in about 0.4 s.
- **Hardhat's in-process network took about 33 s to load**, which rules it out inside requests and per-test hooks. A **separate `hardhat node` over JSON-RPC HTTP** was ready in about 1.3–2.8 s, with a 14 ms anchor round trip, so that is the architecture for both the app and the tests.
- **Deployed code never equals solc's runtime bytecode**, because the immutable `owner` is filled in at deployment. Contract identity is therefore checked with solc's `immutableReferences` masked; the raw comparison fails and the masked one succeeds.
- The contract's custom errors (`AlreadyAnchored`, `NotOwner`, `EmptyRoot`) decode over HTTP, while the in-process transport only surfaced "unknown RPC error".
- A restarted node has a **new genesis hash and none of the old state**, which is how a reset is recognised.

### What changed

- **`lib/crypto/merkle.ts`**: RFC 6962 Merkle tree hash (0x00 leaf / 0x01 node prefixes, the RFC's split for unbalanced trees), audit paths, and the RFC 9162 §2.1.3.2 inclusion-verification algorithm.
- **`contracts/OmniTrustAnchor.sol`**: owner-only `anchor(bytes32 root, uint32 leafCount)`, one anchoring per root, a non-zero root, an `Anchored` event carrying the leaf count; no payable function. **`scripts/compile-anchor-contract.ts`** (`npm run contract:compile`, `--check`) compiles it reproducibly with pinned settings into the committed `lib/anchoring/anchor-contract.json`, which includes the source hash.
- **`lib/anchoring/chain.ts`**: viem client for `ANCHOR_RPC_URL` (default `http://127.0.0.1:8545`); deploy, submit (simulated first, so refusals carry the contract's error name), read; an unreachable node is `ChainUnavailableError` (503), a refusal is `AnchorRejectedError` (409).
- **`lib/anchoring/service.ts`** (models `AnchorContract`, `AnchorBatch`, `AnchorLeaf`):
  - commitments are SHA-256 over a versioned, line-based record of identifiers and hashes: for a signature, its id, document-version hash, SHA-256 of the signature value, certificate serial and algorithm; for an audit checkpoint, its id, sequence and checkpoint hash;
  - `anchorPending()` (ADMIN) anchors every not-yet-anchored signature and checkpoint as one root, deploying the contract on first use per chain instance; each item is anchored at most once;
  - `verifyAnchor()` returns VALID / INVALID / UNAVAILABLE / NOT_ANCHORED. It checks that the item's commitment recomputes to the anchored leaf, the stored batch rebuilds the root, the inclusion proof verifies, the answering chain is the recording instance (chain id and genesis hash), the address holds the anchor contract (masked code), the contract records the root in the recorded block, and the `Anchored` event carries the same leaf count and transaction. The last check matters: **an RFC 9162 inclusion proof does not by itself bind the tree size** (see below), so the anchored leaf count is what does.
- **API and UI**: `GET /api/anchoring` (any reader), `POST /api/anchoring/batches` (ADMIN), `GET /api/anchoring/verify?kind=&target=`; an `/anchoring` page (in the navigation) with chain status, pending counts, an admin "Anchor" button, the limits above, and batches marked "current" or "chain gone". New capabilities `anchor:read` (all roles) and `anchor:create` (ADMIN); audit actions `ANCHOR_CONTRACT_DEPLOYED`, `ANCHOR_BATCH_CREATED`.
- **Tests start their own chain**: `tests/global-setup.ts` launches a Hardhat node on port 8546 (apart from `npm run chain` on 8545) and stops it when the suite ends. Its stdout is discarded, because Hardhat prints its development account keys there.

### Findings during this phase

1. **Inclusion proofs do not bind tree size.** A test expecting leaf 3's proof from a 7-leaf tree to fail for a claimed size of 8 was wrong: in both trees leaf 3 sits in the same left subtree of 4, so the RFC 9162 walk takes the same directions and verifies. RFC 9162 authenticates size through the signed tree head. The test now asserts sizes that change the path shape fail, documents the size-8 case as a property, and anchor verification compares the on-chain leaf count.
2. **The Merkle implementation was checked against published vectors**: it reproduces the Certificate Transparency reference roots for 1 to 8 of its standard test leaves, including the unbalanced sizes 3, 5, 6 and 7, plus the empty tree.
3. **An existing RBAC test pinned VIEWER's exact capability list** and correctly failed when the read-only `anchor:read` was added. It was updated, and a test now asserts audit checkpoints and anchoring are ADMIN-only.

### Verification

- `npm test`: **628 passed, 1 skipped** across 42 files (589 after Phase 6). New tests:
  - `tests/crypto/merkle.test.ts` (21): the CT vectors, leaf/node domain separation, no collision with a duplicated last leaf, proofs for every leaf of every size 1–8 and larger random trees, and rejection of a different leaf, wrong index, shape-changing sizes, tampered, truncated or extended proofs, a different root, and malformed input without throwing.
  - `tests/anchoring/anchoring.test.ts` (17), against a real local chain: the committed artifact equals a fresh compile and has no payable function; non-admins are refused and an unreachable chain is `ChainUnavailableError`; three signatures and a checkpoint anchor as one 4-leaf root that the contract records in the batch's block; the transaction input is exactly selector + root + leaf count with zero value, and contains no document hash or signature bytes; nothing pending is 409; every item verifies VALID with a proof re-checked independently; a later signature is NOT_ANCHORED until a second batch with a new root; INVALID for a signature altered after anchoring, an altered sibling leaf, a genuine anchor contract that never saw the root, and an address without the contract; UNAVAILABLE when the recording chain instance is gone or no chain answers; the contract refuses a duplicate root (`AlreadyAnchored`) and a non-owner (`NotOwner`).
- Over real HTTP against `npm run dev`, with a chain the check script started on 8545:
  - viewer overview 200 with 13 pending (12 signatures, 1 checkpoint); anchoring refused for a viewer (403), cross-site (403) and without a session (401);
  - admin anchoring 201: 13 leaves in block 2; a repeat returns 409;
  - a signature (leaf 0, 4 proof nodes) and the audit checkpoint (leaf 12) verify VALID with all seven checks passing; an unknown kind is 400;
  - an independent viem read shows the contract recording the root at block 2, and the transaction input is 68 bytes with zero value;
  - with the chain stopped, verification is UNAVAILABLE ("cannot be reached") and the overview reports it unreachable; after a restart it is UNAVAILABLE ("chain instance is gone") and the batch is shown as not on the current chain.
- Browser, `/anchoring` as admin after that check: "UNAVAILABLE" with the reason, the limits, and the batch marked "chain gone"; the Anchoring navigation link; no console errors. **Consequence for the demo database:** its 13 anchors belong to a chain instance that no longer exists and will always verify UNAVAILABLE, exactly as documented.
- `tsc --noEmit`, `npm run lint`, `npm run check:boundary`, `npm run build`, `npm run contract:compile -- --check`: clean.

---

## Phase 8 — Security Lab (attack console on disposable data)

### Isolation, the governing requirement

Attack scenarios deliberately corrupt documents, signatures, CRLs and the audit log. They must never be able to reach the application's own data, so isolation is structural rather than a convention:

- **A separate process per run.** `lib/security-lab/sandbox.ts` creates `<lab root>/runs/<run id>/` with a copy of a pre-migrated template database, its own document storage and a freshly generated master key. It then starts `scripts/security-lab-runner.ts` in a child process whose `DATABASE_URL`, `STORAGE_ROOT` and `MASTER_KEY_PATH` point only there, with a random `JWT_SECRET` and an unreachable chain URL. The web server process never runs an attack.
- **A guard every scenario passes first.** `assertSandbox()` refuses unless the database, storage root and key all lie inside the same run directory and the lab flag is set. The only other acceptance is the throwaway `test.db` with `storage/test` while Vitest runs. A lab-shaped database paired with the real storage or key, parts spread over two runs, or the development database is refused.
- **Deleted afterwards.** The run directory is removed after every run, including failed ones, and the result says whether removal succeeded.
- **Evidence, not assertion.** The service records the application database's record counts and audit-chain head before and after each run and reports whether they are identical. The only change allowed is the `SECURITY_LAB_RUN` audit entry appended after that comparison.
- **Template reuse.** The template is migrated once and rebuilt only when the committed migrations change (fingerprinted by content), so a run takes about 1.7 s rather than re-migrating.
- **Admin-only** (`lab:run`), one run at a time (a second concurrent request is 409), and every run is audited with its outcome.

### Scenarios

Fifteen, each implemented against the real services (`lib/security-lab/scenarios.ts`, catalogue in `catalog.ts`). Each reports **HELD / FAILED / ERROR** together with the expected result, the observed result, the steps and the evidence:

| Scenario | Holds if |
| --- | --- |
| Control: untouched signed document | VALID (shows the lab is not rigged to fail) |
| Substitute stored bytes with validly encrypted content | INVALID / HASH_MISMATCH |
| Flip one ciphertext bit | INVALID / HASH_MISMATCH (AES-GCM tag) |
| Corrupt the signature | INVALID / SIGNATURE_INVALID |
| Replay a genuine signature and time-stamp onto another document | INVALID / SIGNATURE_INVALID |
| Relabel signature and certificate as another registered algorithm | INVALID / ALGORITHM_MISMATCH |
| Point the signature at a certificate of another algorithm | INVALID / ALGORITHM_MISMATCH |
| Key compromise reported after signing, no invalidity date | INVALID / CERTIFICATE_REVOKED |
| Swap in another signature's genuine time-stamp | INVALID / TIMESTAMP_INVALID |
| Forge the stored CRL | UNVERIFIABLE / REVOCATION_STATUS_UNAVAILABLE, never VALID |
| Verify the CMS export against altered content | CMS INVALID (and VALID for the original) |
| Edit an audit row | chain breaks at exactly that entry |
| Rewrite the audit log and recompute every hash | chain check fooled; checkpoint reports LOG_REWRITTEN |
| Delete the newest audit entries | chain check fooled; checkpoint reports LOG_TRUNCATED |
| Brute-force a password | locked after 5 failures; the correct password is then refused |

Algorithms are chosen from the registry and the CA policy, so the boundary checker still finds no algorithm literal outside `lib/crypto`. The brute-force scenario exercises the same limiter and `authenticate()` in the login route's order (limiter first); it does not call the HTTP route itself, and says so.

### What changed

- `lib/security-lab/{guard,catalog,scenarios,sandbox,service,protocol}.ts`, `scripts/security-lab-runner.ts`.
- `GET /api/security-lab` (scenario list) and `POST /api/security-lab` `{scenario}` (run), both ADMIN.
- `/security-lab` page: a card per scenario with its attack, control and pass condition, a Run button, and the result with steps, sandbox deletion and the unchanged-database evidence. It is in the navigation.
- Capability `lab:run` (ADMIN) and audit action `SECURITY_LAB_RUN`.

### Verification

- `npm test`: **652 passed, 1 skipped** across 43 files (628 after Phase 7). New `tests/security-lab/security-lab.test.ts` (24):
  - the catalogue is fully implemented with unique ids and includes a control;
  - **all 15 scenarios run for real against the test database and report HELD**;
  - the guard accepts a complete run directory and refuses the development database (even with `VITEST` set), a sandbox database with the real storage or key, a lab path without the flag, parts from two runs, and a scenario started in a process not pointed at a sandbox;
  - admin-only listing and running, and unknown scenarios refused;
  - **a full child-process run** reports HELD with `INVALID / HASH_MISMATCH`, deletes its run directory, leaves the calling database's document count unchanged, and is audited with `productionUntouched: true`; a second run reuses the template.
  - The RBAC test now also asserts `lab:run` is ADMIN-only.
- Over real HTTP against `npm run dev`:
  - listing and running are refused for a verifier (403), cross-site (403) and without a session (401), and an unknown scenario is 400;
  - the control, forged-CRL and consistent-rewrite scenarios each returned HELD in about 1.7 s, with the sandbox removed and the application database identical before and after (13 documents, 12 signatures, 5 CRLs; only the lab's own audit entries were added afterwards);
  - a second run started during one returned 409;
  - `storage/lab/runs` was empty afterwards.
- Browser, `/security-lab` as admin: running "Flip one bit of the encrypted blob" showed CONTROL HELD, the sandbox id marked deleted, and the unchanged-database note; no console errors.
- `tsc --noEmit`, `npm run lint`, `npm run check:boundary`, `npm run build`: clean.

---

## Phase 9 — Interface redesign around real evidence

### Principle

Every new view renders data the system actually holds, read at request time: registry metadata, database counts, parsed certificate bytes, the authenticated CRL, the audit log, or benchmark files measured on this machine. No figure is illustrative. Where a value is only what was stored (for example the latest CRL row, or anchors whose chain may be gone), the wording says so.

### What changed

- **Navigation**: grouped as Overview, Records, Trust, Integrity and Evaluation, with the current page highlighted (`aria-current`) and a sticky header.
- **Dashboard** (`lib/dashboard/overview.ts`):
  - counts of documents, signatures (time-stamped and with a CMS export) and certificates by status;
  - distribution bars for document lifecycle states and signatures by algorithm;
  - trust services: root CA, Time-Stamp Authority and the latest issued CRL with its freshness;
  - integrity: audit entries, signed checkpoints, and entries since the latest checkpoint;
  - anchoring, worded to point at the anchoring page for whether its chain still exists;
  - the last eight verifications from the audit log, with VALID / INVALID / UNVERIFIABLE / ERROR kept distinct;
  - recent activity and the user's capabilities.
- **Algorithms page** (`/algorithms`):
  - a comparison of every registered provider: class, security level, key and signature sizes, determinism, measured medians where `npm run benchmark` has produced them (otherwise "not measured"), and live certificate and signature counts;
  - a detail card per algorithm: standards, implementation, quantum resistance, message processing, OIDs and CMS identifiers, and which independent check applies;
  - a crypto-agility section naming the tests and checks that back the claim.
- **Certificate explorer** (`/certificates/[id]`, `lib/pki/explorer.ts`; linked from the certificates table):
  - trust chain: root CA to end-entity, each with a SHA-256 fingerprint, plus every validation check;
  - fields parsed from the X.509 structure: subject, issuer, validity, the key algorithm identified from the key material, basic constraints, key usage, extended key usage, and the PEM;
  - revocation read from the authenticated CRL, reported as UNAVAILABLE (never "not revoked") when the CRL cannot be authenticated;
  - the key-lifecycle state machine with its current and legal next states, and the certificate's and key's history from the audit log;
  - the signatures made with the key.
- **Verification screen**: an evidence-chain strip (Certificate, Revocation, Time-stamp, Key, Signature, Content), each link coloured by its real step status, above the full ten-step list.
- **Audit log**: the entries table is replaced by a timeline grouped by day and coloured by category (security, access, documents, PKI, integrity, lab), still showing each entry's chained hash prefix and details.
- **Document versions** show which signature, algorithm and signer each version carries, or "unsigned".

### Found during checking

- The first dashboard wording said the anchored items were "on the local chain". After Phase 7's restart test that chain instance no longer exists, so the claim was untrue. It now links to the anchoring page, which reports the chain's actual state.
- In a narrow browser pane the grouped navigation wraps onto several lines. A click computed from an earlier layout landed on a navigation link instead of the intended button; the check was repeated after scrolling the button into view. The wrap is functional but takes vertical space on small screens, and is left for a later responsive pass.

### Verification

- `npm test`: **658 passed, 1 skipped** across 45 files (652 after Phase 8). New tests:
  - `tests/dashboard/overview.test.ts` builds a known state through the real services and checks every count, the recent verification's verdict and filename, and the trust-service and integrity figures;
  - `tests/pki/explorer.test.ts` checks the fingerprint and serial against `node:crypto`'s independent X.509 parser, the extensions and chain, the lifecycle through revocation (issued, key ACTIVE, revoked, key REVOKED) with the CRL-derived reason, and UNAVAILABLE revocation for a forged CRL.
- Browser, as admin against the development database:
  - the dashboard showed 13 documents, 12 signatures (7 time-stamped, 4 with CMS), 12 certificates (8 active, 3 revoked, 1 expired), CRL #5, and recent verifications including `INVALID / CERTIFICATE_REVOKED` and `INVALID / HASH_MISMATCH`;
  - the algorithms page listed four providers with measured medians for three and "not measured" for ML-DSA-65, which the saved benchmark file predates;
  - the explorer for the Phase 4c key-compromise certificate showed the chain with fingerprints, "Not revoked" failing, CRL #5 `keyCompromise`, key state REVOKED (next RETIRED), and its four lifecycle events;
  - verifying `phase4c-affiliation.txt` showed AUTHENTIC with all six evidence-chain links PASS, consistent with the ten steps;
  - the audit timeline rendered;
  - no console errors on any page.
- `tsc --noEmit`, `npm run lint`, `npm run check:boundary`, `npm run build`: clean.

---

## Phase 10 — Statistically rigorous benchmarks

### What changed

- **`lib/benchmarks/statistics.ts`**, pure and unit-tested. Every definition is stated so results can be reproduced elsewhere:
  - n, mean, and the **sample** standard deviation (n − 1), with the standard error;
  - a **95% confidence interval for the mean** using Student's t from a table, taking the next lower tabulated degrees of freedom (conservative, slightly wider); none is reported for a single sample;
  - median and percentiles by linear interpolation (Hyndman & Fan type 7, the NumPy and R default), replacing the earlier floor-index percentile;
  - min, max, p5, p95 and the coefficient of variation;
  - **outliers counted with Tukey's fences and never removed**.

  The module states the caveat that timing samples are right-skewed and not strictly independent, so medians come first and the interval is indicative.
- **`scripts/benchmark.ts`**:
  - defaults of n = 200 per sign, verify and hash measurement, n = 20 key generations (was 5) and 20 warm-up iterations (was 5), all configurable;
  - a written methodology inside the output;
  - an extended environment record: Node, V8, OpenSSL, OS, CPU model and speed, cores, memory and free memory at start, load average where the OS provides it, git commit and whether the tree was dirty, start time and duration;
  - `--smoke` for CI (small n, written to `storage/benchmarks-smoke.json` so real results are never overwritten) and `--output`.
- **`/benchmarks`** shows n, median, mean with its 95% CI, SD and CV, min / p95 / max and outlier counts for signing, verification, hashing by payload size and key generation. It also shows the environment and methodology, and flags smoke runs and files from the earlier schema.
- **`tests/crypto/benchmark-output.test.ts`** now requires, for a current-schema file:
  - internally consistent statistics: n as configured, ordered min ≤ p5 ≤ median ≤ p95 ≤ max, SE = SD / √n, CV = SD / mean, and a CI containing the mean;
  - every registered algorithm present (except in a smoke run);
  - the environment and methodology recorded.

### Measured on this machine

`npm run benchmark` on an AMD Ryzen 7 8840HS (16 logical cores), Windows 11, Node 24.14.0, OpenSSL 3.5.5, took 15.4 s. This is the first file to include ML-DSA-65. Signing, n = 200 each:

| Algorithm | Median | Mean [95% CI] | SD (CV) | Outliers |
| --- | --- | --- | --- | --- |
| RSA-PSS 3072 | 2.150 ms | 2.358 [2.297, 2.419] ms | 0.435 (18%) | 29 |
| ECDSA P-256 | 0.128 ms | 0.162 [0.139, 0.185] ms | 0.167 (103%) | 9 |
| EdDSA Ed25519 (@noble, pure JS) | 0.934 ms | 1.019 [0.977, 1.062] ms | 0.303 (30%) | 10 |
| ML-DSA-65 | 1.684 ms | 2.025 [1.858, 2.191] ms | 1.191 (59%) | 8 |

Reading the table: the means sit above the medians and the CVs are large (ECDSA's 103% comes from a few multi-millisecond pauses against a 0.13 ms median), which is exactly why medians are presented first. The run recorded commit `3c06433` with uncommitted changes, because it measured this phase's code before it was committed. As before, the Ed25519 figures describe `@noble/ed25519` on this runtime, not EdDSA in general.

### Bugs found during this phase

Both surfaced as intermittent Security Lab failures while the full suite ran alongside a build and a benchmark. Neither was dismissed as a flake.

1. **A fresh installation's first signature could receive an invalid time-stamp.**
   - `issueTimestampToken` took its genTime on entry, then created the Time-Stamp Authority if none existed.
   - When that creation crossed a second boundary, the authority certificate's `notBefore` (whole seconds) fell one second after the token's genTime. The verifier then correctly refused the token as issued outside its authority's validity: INVALID, `TIMESTAMP_INVALID`.
   - Diagnosis: 16 sandboxed control runs (8 idle, 8 under CPU load) did not reproduce it, which pointed at a narrow timing window rather than load.
   - Reproduction: `tests/pki/tsa-clock.test.ts` fakes only `Date` and moves it past a second boundary at the moment the authority is found missing. Against the unfixed code it failed with `token genTime 18:12:23.000Z, authority notBefore 18:12:24.000Z`.
   - A first version of that test compared the database row's `createdAt`, which the database engine sets on the real clock. It failed for the wrong reason, was corrected to use the certificate's own `notBefore`, and only then shown to fail on the bug.
   - Fix: take genTime after the authority exists. An explicit `at` is still honoured, so the test that a back-dated token is refused still holds.
2. **A certificate whose validity had not yet begun was reported as "expired".**
   - The key-substitution scenario signed first and issued the substitute certificate afterwards. When that issuance landed in a later second than the signature's time-stamp, verification (judging at the trusted signing time) refused the certificate, correctly, as outside its validity, but named it `CERTIFICATE_EXPIRED`.
   - RFC 5280 path validation distinguishes "not yet valid" from "expired". Validation now reports **`CERTIFICATE_NOT_YET_VALID`** when the evaluation time is before `notBefore`, and verification carries it as an INVALID reason with its own explanation.
   - `tests/verification/not-yet-valid.test.ts` covers validation, a signature proven to predate the certificate it names, and refusal to sign with such a certificate. The existing "fails before the window opens" expectation was updated.
   - The scenario now issues the substitute before signing, so it deterministically demonstrates `ALGORITHM_MISMATCH`, and its tests print the observed verdict and evidence on failure.

### Verification

- `npm test`: **673 passed, 1 skipped** across 48 files (658 after Phase 9). New: statistics (9), the time-stamp clock regression (1), not yet valid (3), and the extended benchmark-output checks. The Security Lab tests plus both regressions then passed **three consecutive runs** (28/28 each).
- The smoke run wrote schema 2 with n = 10 for all four algorithms and left `public/benchmarks.json` byte-for-byte unchanged (SHA-256 compared).
- Browser, `/benchmarks`: n, median, mean with CI, SD and CV, min / p95 / max and outliers, together with the environment (including OpenSSL 3.5.5, V8 and the git commit marked as having uncommitted changes) and the methodology; no console errors.
- `tsc --noEmit`, `npm run lint`, `npm run check:boundary`, `npm run build`: clean.

---

## Phase 11 — Route-level tests, and an API that leaked encrypted private keys

### The gap

Of the 22 route handlers under `app/api`, only 8 were imported by any test. The rest were exercised only through their service functions, so session lookup, input validation, status mapping and response shaping in the handlers themselves were untested. The Phase 0 audit had recorded this gap.

### What changed

- **`tests/api/routes.test.ts`** runs the 14 untested handlers for real; only `next/headers` is replaced, because it exists only inside a Next.js request scope. The routes are `auth/me`, documents (list, upload, detail, versions), sign, verify, certificates (list, issue, revoke), audit verify and checkpoints, the three anchoring routes (against the test chain) and the Security Lab. Where a route has them, each is checked for:
  - 401 when signed out, and 403 for a role without the capability;
  - 400 for malformed input and 404 for unknown ids;
  - 409 for conflicts: duplicate upload, re-signing, re-revoking, nothing to anchor, and verifying an unsigned document (`notSigned: true`);
  - the success status and response shape.

  Security Lab runs are checked for refusals only, since real sandboxed runs are covered in `tests/security-lab`.
- **Every response body in that file is checked** for `PRIVATE KEY`, `encryptedPrivateKey`, `passwordHash`, bcrypt hashes and stack traces.
- **`tests/api/route-coverage.test.ts`** enumerates every `app/api/**/route.ts` and fails if no test imports it, so a new route cannot be added without a route-level test. All 22 routes are now imported.

### Security finding, fixed

**`POST /api/certificates` returned the new certificate's encrypted private key.** The route passed `issueCertificate`'s record straight to the response, and that record includes the key pair with its `encryptedPrivateKey` column.

- **Exposure:** the AES-256-GCM ciphertext of the private key, readable only with the server's local master key, sent to whoever issued the certificate (the subject, or an admin issuing for another user). This was the live behaviour of the running app since certificate issuance was built.
- **Why it matters:** it breaks the brief's rule that no API may expose private-key material, and it removed a layer of defence. Anyone who later obtained the master-key file would no longer need database access to decrypt keys from captured responses.
- **How it was found:** the new body check failed on the five tests that issue certificates through the route, before any fix.
- **Fix:** the route now returns the certificate with the key pair reduced to `id`, `status` and `algorithm`, the same view the list and detail routes already gave. The certificate issue form only reads `error` from the response, so it is unaffected. The other routes' bodies passed the same check.
- **Not done:** keys issued before the fix are unchanged. A ciphertext already delivered cannot be recalled, and rotating the demo master key is outside this phase; the limitation is recorded here.

### Verification

- `npm test`: **687 passed, 1 skipped** across 50 files (673 after Phase 10). New: `tests/api/routes.test.ts` (13 tests, each checking several routes and statuses) and `tests/api/route-coverage.test.ts` (1). The five certificate-related route tests failed on the leak before the fix and passed after it; the API tests then ran 23/23.
- The fix is exercised through the real route handler in the tests; it was not re-checked over HTTP against `npm run dev`.
- `tsc --noEmit`, `npm run lint`, `npm run check:boundary`, `npm run build`: clean.

---

## Phase 12 — Local CI: `npm run ci`

### What changed

- **`scripts/ci.ts`** runs every quality gate locally, with no network access and no hosted CI service. The steps, in order:
  1. installed dependencies match `package.json` (`npm ls --depth=0`, offline);
  2. the Prisma schema validates;
  3. the anchor contract artifact is a reproducible compile;
  4. ESLint;
  5. TypeScript type-check;
  6. the crypto-boundary check;
  7. the **unit**, **integration** and **security** test suites;
  8. the production build;
  9. a benchmark **smoke run**, whose output is also checked in-process: schema 2, every registered algorithm, plausible statistics.
- **Behaviour of the runner:**
  - each tool is started as `node <entry point>`, because spawning npm/npx `.cmd` shims without a shell fails on Windows;
  - output streams live, and the last 40 lines of a failing step are kept;
  - a warning is printed if something listens on port 3000 before the build, since `next dev` and `next build` share `.next`;
  - it ends with a PASS / FAIL / SKIPPED summary and a JSON report in `storage/ci/report.json` (gitignored) recording node, platform, git commit and dirty flag;
  - options `--fail-fast`, `--only a,b` and `--skip a,b`; unknown step names are refused;
  - it exits 0 only if every selected step passed.
- **Test suites** are defined by directory: unit is `crypto`, `benchmarks`, `ci` and the scaffold test; integration is `documents`, `pki`, `audit`, `anchoring`, `prisma`, `dashboard` and `verification`; security is `auth`, `http`, `api` and `security-lab`.
- **`tests/ci/ci-plan.test.ts`** checks the plan without running CI recursively:
  - every test file belongs to exactly one suite, so a new test cannot fall outside CI, and every suite entry exists;
  - every step's program exists;
  - the static gates and all three test suites run before the build, and the smoke run comes last;
  - `npm run ci` is wired to the runner, and its reports are gitignored.

### Verification

- **`npm run ci`, full run: CI PASSED in 237 s**, all 11 steps PASS:

  | Step | Time |
  | --- | --- |
  | dependencies | 1 s |
  | prisma-schema | 2 s |
  | contract-artifact | 1 s |
  | lint | 3 s |
  | typecheck | 5 s |
  | crypto-boundary | 0 s |
  | tests-unit: 211 passed, 1 skipped | 16 s |
  | tests-integration: 369 passed | 97 s |
  | tests-security: 111 passed | 70 s |
  | build | 39 s |
  | benchmark-smoke | 2 s |

  The three suites total **691 passed, 1 skipped**: the 687 after Phase 11 plus the 4 plan tests. The run recorded commit `abd2d56` with this phase's files uncommitted. Its output is kept in `storage/ci/ci-run.log`; the report file was later overwritten by the option checks below.
- **Option handling and failure detection:**
  - `--only no-such-step` is refused with the list of valid steps and exit code 1;
  - `--only crypto-boundary` runs that step alone, marks the rest "not selected", and exits 0;
  - a genuine failure, produced without changing any code by running from a copy of `node` that cannot locate npm, reports `FAIL dependencies — npm's JavaScript entry point was not found` and `CI FAILED (1 step)`, and exits 1.
- The full CI run includes type-check, lint, the boundary check and the build.

---

## Phase 13 — Security audit

The audit is recorded in **[`docs/audit/02-security-audit.md`](audit/02-security-audit.md)**: scope, findings with severity and status, the controls verified with the test that backs each, and the accepted limitations.

### Findings

| ID | Severity | Finding | Status |
| --- | --- | --- | --- |
| S1 | High (policy) | `POST /api/certificates` returned the encrypted private key | Fixed in Phase 11 |
| S2 | Medium | Unauthenticated `GET` routes changed state (TSA creation, CRL issuance) | **Fixed in this phase** |
| S3 | Medium | First time-stamp could predate its authority certificate | Fixed in Phase 10 |
| S4 | Low | Not-yet-valid certificate reported as expired | Fixed in Phase 10 |
| S5 | Low | README limitations understate the implemented controls | Open, for Phase 15 |

Ten accepted limitations (L1–L10) are stated in the audit: stateless sessions, in-memory throttling, CSP `'unsafe-inline'`, a production-only `secure` cookie, a local master-key file, role-based rather than ownership-based read access, a framework-default body limit, a public development chain account, no offline dependency-advisory scan, and demo-grade trust anchors.

### Fixed in this phase: state changes on unauthenticated GET

- `GET /api/pki/tsa` created the Time-Stamp Authority on first request: a key generation, a CA signature and database writes. `GET /api/pki/crl` made the CA sign a new list whenever the stored one had lapsed. GET is exempt from the cross-site check and needs no session, so anyone could trigger both.
- Both routes are now read-only. They use the new `activeTimestampAuthority()` and `latestCrl()`, which never create or sign anything. They return 404 when nothing exists yet. A lapsed list is served as stored, with its next-update time also in `X-CRL-Next-Update`, so a consumer can see it is stale.
- Issuance remains with revocation and authenticated verification, which already call `currentCrl()` and `ensureTimestampAuthority()`.
- `tests/pki/public-routes-readonly.test.ts` checks that no row and no `TSA_CREATED` or `CRL_ISSUED` audit entry is created on a 404, and that a lapsed list is served byte-for-byte without a new one being issued.
- The existing TSA and CRL route tests had relied on the side effect and failed after the change. They now create the authority or issue the list explicitly first.

### Verification

- `npm test`: **695 passed, 1 skipped** across 52 files (691 after Phase 12).
- All 18 test files cited in the audit document were checked to exist.
- The S2 fix is verified through the real route handlers in tests; it was not re-checked over HTTP against `npm run dev`.
- `tsc --noEmit`, `npm run lint`, `npm run check:boundary`, `npm run build`: clean.

---

## Phase 14 — End-to-end regression against an isolated production installation

### What changed

- **`scripts/e2e.ts`** (`npm run build && npm run e2e`) regression-tests the whole application over real HTTP, against a separate installation rather than the development one:
  - it creates `storage/e2e/<run id>/` with a new SQLite database, its own document storage, a freshly generated master key, a random JWT secret and its own Security Lab root;
  - it applies the committed migrations and seeds through the real services;
  - it starts its own local chain on port 8547, with stdout discarded because Hardhat prints its development keys there;
  - it runs the **production build** with `next start` on port 3100, apart from the dev server (3000), `npm run chain` (8545) and the test chain (8546).
- **Checks, in order:**
  1. migration and seeding, including an intact audit chain;
  2. both servers start;
  3. the login page renders with its security headers and without `X-Powered-By`, and a protected page redirects to login when signed out;
  4. all four roles sign in, and all eight application pages render for an admin without key material;
  5. every seeded signed sample verifies VALID with a trusted time, the pre-tampered invoice is `INVALID / HASH_MISMATCH`, and the unsigned draft returns 409 "not signed";
  6. for every registered algorithm: issue a certificate, upload, sign and verify VALID;
  7. the CMS exports for RSA-PSS and ECDSA verify with `openssl cms -verify` (skipped, and reported as skipped, if OpenSSL is absent);
  8. a `keyCompromise` revocation makes a signature `INVALID / CERTIFICATE_REVOKED`, and the downloaded CRL lists "Key Compromise" in OpenSSL;
  9. a cross-site POST, a viewer issuing a certificate, a signer anchoring and an unauthenticated document list are all refused;
  10. the audit log verifies, and a signed checkpoint is created and reconciled;
  11. pending commitments anchor and an anchor verifies VALID;
  12. a Security Lab control run holds with the installation's data untouched;
  13. five wrong passwords lock the account, so the correct password returns 429;
  14. logout expires the session cookie;
  15. **the development database's SHA-256 is identical before and after**.

  Every API response body is also checked for key material and password hashes.
- **Cleanup and reporting:** the isolated installation is deleted afterwards, `storage/e2e/report.json` keeps the results and a server log tail on failure, and the script exits non-zero if any step fails.
- **`tests/ci/e2e-plan.test.ts`** checks the isolation plan without starting servers:
  - every path lies inside the run directory under the gitignored `storage/`;
  - the development database, storage and key are never referenced;
  - the ports avoid 3000, 8545 and 8546;
  - a new JWT secret is generated each run;
  - `npm run e2e` runs this script.

### Found during this phase

The first version of `scripts/e2e.ts` hashed the development database with `createHash` from `node:crypto`. That breaks the project's own rule that cryptographic primitives live only in `lib/crypto`. The rule's enforcement caught it: the full suite failed four boundary and agility tests, and `npm run check:boundary` reported `scripts/e2e.ts:12`. The script now uses `sha256Hex` from `lib/crypto/hash`.

### Verification

- **`npm run e2e`: E2E PASSED, 17 of 17 steps, in 15.4 s**, exit code 0. The results were:
  - 28 audit entries after seeding;
  - 4 seeded samples VALID;
  - 4 algorithms signed and verified end to end;
  - OpenSSL verified the RSA-PSS and ECDSA CMS exports;
  - 73 entries verified after a checkpoint;
  - 10 commitments anchored in block 2;
  - the isolated installation was removed and the development database was unchanged.

  The run was repeated after the boundary fix with the same result.
- **Negative control:** to show the harness can fail, a fake HTTP server that answers like a live service but is not a blockchain node was put on the E2E chain port.
  - Only the anchoring step failed, with `503 No local chain is answering at http://127.0.0.1:8547`.
  - The run reported `E2E FAILED: 16 passed, 1 failed` and exited 1.
  - The isolated installation was still removed and the development database was still untouched.
- `npm test`: **699 passed, 1 skipped** across 53 files (695 after Phase 13), including the four E2E plan tests.
- `tsc --noEmit`, `npm run lint`, `npm run check:boundary`: clean. The production build used was made after the last application change, in Phase 13; this phase changed no application code.

---

## Phase 15 — Documentation, final implementation report and demo script

### What changed

- **`README.md` rewritten** against the code as it now is:
  - four algorithms, including ML-DSA-65, and the **Node 24** requirement (ML-DSA needs its OpenSSL 3.5; the old README said Node 20);
  - the ten-step verification with all four verdicts and every reason code;
  - the timestamp-aware revocation policy, with the OmniTrust-specific rule marked as such;
  - CMS export and the OpenSSL command, with the Ed25519 and ML-DSA limitation;
  - checkpoints, anchoring, the Security Lab, benchmarks, `npm run ci` and `npm run e2e`;
  - every environment variable;
  - a corrected limitations section. It no longer claims there is no CRL, no rate limiting or only SameSite CSRF protection (security audit finding S5); it adds the anchoring, session, role-based access and dependency-scanning limits.
- **`DEMO_SCRIPT.md` rewritten as 23 steps** in six parts, using the interface's exact labels. The revocation section now shows the timestamp-aware policy rather than hiding it:
  - an ECDSA certificate revoked for `affiliationChanged` leaves its document **AUTHENTIC** (`SIGNED_BEFORE_REVOCATION`);
  - an RSA certificate revoked for `keyCompromise` with no invalidity date makes its document **INVALID** (`COMPROMISE_TIME_UNKNOWN`).

  The old script revoked with the form's default reason (`superseded`), which under the new policy would have left the document valid and contradicted the script. The new script requires a fresh setup and explains the symptom otherwise.
- **`docs/final-implementation-report.md`**: 20 sections, each item marked IMPLEMENTED, PARTIAL, LIMITED BY LIBRARY or NOT IMPLEMENTED, with the evidence for each. It collects the 11 bugs found during the upgrade and everything not implemented.
- **`PROGRESS.md`** keeps the original build record as written, with a closing section pointing to the upgrade log, final report, audit and current documentation, and noting which of its statements are historical.
- **`docs/audit/02-security-audit.md`**: S5 marked fixed.
- **`tests/ci/docs-claims.test.ts`** guards the documents against drift:
  - every `npm run` command named in the README, demo script and report exists;
  - every seeded filename they name is one the fixtures create;
  - every local link resolves;
  - the removed limitations do not reappear.

### How the demo script's claims are backed

- The revocation contrast (steps 14–17) is `tests/verification/timestamp-aware.test.ts`.
- The OpenSSL CMS check (step 11) is exercised by the E2E run.
- The Security Lab rewrite attack (step 21) is exercised by the Security Lab tests.
- The seeded filenames, commands and links are checked by the docs test.
- The script was not walked click by click in a browser in this phase; the individual screens were checked in Phases 4c–10.

### Verification

- **`npm run ci`: CI PASSED in 245 s**, all 11 steps. The suites were unit 219 passed and 1 skipped, integration 373, and security 111, for **703 passed, 1 skipped** in total (699 after Phase 14, plus the 4 documentation tests).

---

## Upgrade complete

| Phase | Commit |
| --- | --- |
| 4b — RFC 3161 Time-Stamp Authority | `095f94f` |
| 4c — Timestamp-aware verification | `ccd275f` |
| 5 — CMS export | `9ba1d9d` |
| 6 — Signed audit checkpoints | `bd1f29b` |
| 7 — Merkle anchoring on a local chain | `96bf175` |
| 8 — Security Lab | `890a617` |
| 9 — Interface redesign | `3c06433` |
| 10 — Statistical benchmarks, two timing bugs | `e18e720` |
| 11 — Route-level tests, key-material leak fixed | `abd2d56` |
| 12 — Local CI | `4f78fea` |
| 13 — Security audit | `181babf` |
| 14 — End-to-end regression | `542a09e` |
| 15 — Documentation | this commit |

Phases 0–4a and the ML-DSA addition (`663e26b`) precede this table; `git log` has them all. The final state of every feature is in [`docs/final-implementation-report.md`](final-implementation-report.md).
