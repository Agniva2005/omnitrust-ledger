# OmniTrust Ledger — Final Implementation Report

The state of the project at the end of the 15-phase upgrade. Every item carries one status:

- **IMPLEMENTED**: working, and backed by tests or external verification named here.
- **PARTIAL**: working within a stated boundary; the boundary is named.
- **LIMITED BY LIBRARY**: the implementation is complete, but a library or external tool restricts what can be done or checked independently.
- **NOT IMPLEMENTED**: absent. Listed so that nothing is implied.

Commit hashes refer to this repository. [`docs/upgrade-log.md`](upgrade-log.md) holds the detailed evidence for each phase.

---

## 1. Summary

A local, demo-grade PKI document signing system. It has five signature algorithms, including one post-quantum (ML-DSA-65) and one post-quantum/classical composite (ML-DSA-65 + ECDSA P-256, added after Phase 15 and checked against the IETF draft's published test vectors); ten-step verification with four distinct verdicts; RFC 3161 time-stamping with timestamp-aware revocation; CA-signed CRLs; CMS export verifiable by OpenSSL; a hash-chained audit log with signed checkpoints; Merkle anchoring on a local chain; a sandboxed Security Lab; statistically reported benchmarks; and offline CI and end-to-end regression. At the end of Phase 14: **699 tests passed, 1 skipped**; `npm run ci` passed all 11 steps; `npm run e2e` passed 17 of 17 steps.

## 2. Ground rules followed

| Rule | Status | How it is held |
| --- | --- | --- |
| No hand-rolled cryptography | IMPLEMENTED | Vetted libraries only; the boundary checker confines primitives to `lib/crypto` |
| Local-first, no cloud or paid services | IMPLEMENTED | SQLite, local CA/TSA/chain; `npm run ci` runs offline |
| No private keys or secrets in logs, errors or APIs | IMPLEMENTED | Log redaction; response-body scan on every route (Phase 11 found and fixed a leak) |
| Security Lab only on disposable data | IMPLEMENTED | Separate process and sandbox, isolation guard, before/after evidence |
| Blockchain anchors commitments only | IMPLEMENTED | Only a Merkle root and leaf count reach the chain; checked on the transaction input |
| No cryptocurrency, tokens or NFTs | IMPLEMENTED | The contract has no payable function; checked in tests |
| No AI features | IMPLEMENTED | None present |
| Verdicts never collapsed | IMPLEMENTED | VALID / INVALID / UNVERIFIABLE / ERROR throughout the API and UI |
| No overclaiming | IMPLEMENTED | Limits stated in the UI, the README and this report; no ETSI or CAdES conformance claimed |

## 3. Architecture and layering

| Item | Status | Evidence |
| --- | --- | --- |
| Layered architecture (presentation, auth, documents, crypto, PKI, anchoring, storage, audit, Security Lab) | IMPLEMENTED | `README.md` architecture table; folder structure |
| Algorithm-specific code confined to `lib/crypto` | IMPLEMENTED | `npm run check:boundary` (imports and algorithm literals); `tests/crypto/boundary.test.ts` |
| Algorithm branching detected, not only imports | IMPLEMENTED | The checker reads algorithm ids from the registry |

## 4. Provider abstraction and crypto-agility

| Item | Status | Evidence |
| --- | --- | --- |
| Provider registry with declarative metadata (family, security level, sizes, OIDs, CMS identifiers, interoperability) | IMPLEMENTED | `lib/crypto/registry.ts`, `lib/crypto/types.ts`; numeric claims checked by `tests/crypto/metadata.test.ts` |
| Adding an algorithm touches one provider and the registry | IMPLEMENTED | ML-DSA-65 added in commit `663e26b`; `tests/crypto/agility.test.ts` registers ML-DSA-44 at test time |
| Providers refuse foreign keys (algorithm confusion) | IMPLEMENTED | `tests/verification/algorithm-confusion.test.ts`, `tests/crypto/providers.test.ts` |

## 5. Signature algorithms

| Item | Status | Evidence |
| --- | --- | --- |
| RSA-PSS 3072, ECDSA P-256 (OpenSSL through `node:crypto`) | IMPLEMENTED | OpenSSL CLI verification in tests |
| EdDSA Ed25519 (`@noble/ed25519`) | IMPLEMENTED | RFC 8032 vector; OpenSSL cross-signing |
| ML-DSA-65 (FIPS 204, OpenSSL 3.5 through `node:crypto`) | IMPLEMENTED | Cross-verified with `@noble/post-quantum` from the same seed (`tests/crypto/mldsa-interop.test.ts`) |
| ML-DSA verification with the OpenSSL command-line tool | LIMITED BY LIBRARY | The installed CLIs (3.2.4, 3.4.0) cannot parse ML-DSA keys; the metadata test that runs the CLI is skipped for ML-DSA |
| Requires Node 24 for ML-DSA | PARTIAL | Stated in the README; older Node cannot run the ML-DSA provider |
| Composite ML-DSA-65 + ECDSA P-256 (`id-MLDSA65-ECDSA-P256-SHA512`, draft-ietf-lamps-pq-composite-sigs-19; CMS per draft-ietf-lamps-cms-composite-sigs-05) | IMPLEMENTED | `tests/crypto/composite.test.ts` verifies the draft's published signatures, keys and self-signed certificate (vectors pinned to upstream commit `1bb9f5c6`); each component of an in-app CMS signature is verified independently with `@noble/post-quantum` and `@noble/curves` (`tests/pki/cms-signature.test.ts`); both components are required |
| Composite signatures specified by an RFC | PARTIAL | Both documents are Internet-Drafts in the RFC Editor queue, not yet RFCs; identifiers or encodings may change before publication |
| Composite verification with the OpenSSL command-line tool | LIMITED BY LIBRARY | No released OpenSSL CLI implements composite ML-DSA |

## 6. Verification workflow

| Item | Status | Evidence |
| --- | --- | --- |
| Ten ordered steps with per-step PASS / FAIL / UNAVAILABLE / SKIPPED | IMPLEMENTED | `lib/documents/verification.ts`; `tests/verification/workflow.test.ts` |
| Four verdicts with precise reasons, including `CERTIFICATE_NOT_YET_VALID` (Phase 10) | IMPLEMENTED | `tests/verification/verdicts.test.ts`, `not-yet-valid.test.ts` |
| Explanation and trust summary (trusted time, revocation decision, policy) | IMPLEMENTED | Verify screen and API |
| Storage failure never reported as tampering | IMPLEMENTED | `STORAGE_UNAVAILABLE` is UNVERIFIABLE (verdicts test) |

## 7. Trusted time-stamping

| Item | Status | Evidence |
| --- | --- | --- |
| Local RFC 3161 TSA: critical `id-kp-timeStamping` certificate, CMS SignedData tokens, signingCertificateV2 | IMPLEMENTED | `lib/pki/tsa.ts`; `openssl ts -verify` in `tests/pki/tsa.test.ts` |
| RFC 3161 over HTTP (`POST /api/tsa`) | IMPLEMENTED | `openssl ts -query` round trip in tests |
| Every signature time-stamped over its signature value | IMPLEMENTED | Signing workflow; E2E shows a trusted time on every seeded sample |
| First token on a fresh install never predates its authority (Phase 10 bug) | IMPLEMENTED | `tests/pki/tsa-clock.test.ts` |
| Parsing ESSCertIDv2 with the omitted SHA-256 default | LIMITED BY LIBRARY | `@peculiar/asn1-ess` 2.9.4 cannot parse it; read with `asn1js` instead (Phase 4b) |
| A TSA trusted outside this installation, or a hardware clock source | NOT IMPLEMENTED | The time source is the server clock |

## 8. Revocation

| Item | Status | Evidence |
| --- | --- | --- |
| RFC 5280 reason codes and invalidity dates | IMPLEMENTED | Revoke form and API; `tests/pki/crl.test.ts` |
| CA-signed, numbered CRLs published at `/api/pki/crl` | IMPLEMENTED | `openssl crl -CAfile` and `verify -crl_check` in tests |
| Timestamp-aware revocation policy | IMPLEMENTED | `lib/pki/revocation.ts`; truth table in `tests/pki/revocation-policy.test.ts`; `tests/verification/timestamp-aware.test.ts` |
| Forged or lapsed CRL makes status UNAVAILABLE, never "not revoked" | IMPLEMENTED | CRL tests; Security Lab `forged-crl` |
| Public CRL and TSA routes are read-only (Phase 13 fix) | IMPLEMENTED | `tests/pki/public-routes-readonly.test.ts` |
| Conformance to ETSI EN 319 102-1 | NOT IMPLEMENTED | The no-proof-of-existence rule follows ETSI's indications; full conformance is not claimed |
| OCSP, delta CRLs, intermediate CAs | NOT IMPLEMENTED | — |

## 9. CMS / PKCS#7 export and external verification

| Item | Status | Evidence |
| --- | --- | --- |
| Detached CMS SignedData with signed attributes, both certificates and a signature time-stamp | IMPLEMENTED | `lib/pki/cms-signature.ts`; `tests/pki/cms-signature.test.ts` |
| OpenSSL verification of RSA-PSS and ECDSA exports | IMPLEMENTED | `openssl cms -verify` with CLIs 3.2.4 and 3.4.0; also in the E2E run |
| OpenSSL verification of Ed25519 and ML-DSA exports | LIMITED BY LIBRARY | Those CLIs cannot process them (reproduced with OpenSSL's own Ed25519 CMS); verified instead with `node:crypto` and `@noble/post-quantum` over bytes extracted with `asn1js` |
| Audited export endpoint for CMS, document and certificate | IMPLEMENTED | `app/api/documents/[id]/export/route.ts`; route tests |
| CAdES or PAdES profile conformance, PDF signing | NOT IMPLEMENTED | Not claimed |

## 10. Audit log

| Item | Status | Evidence |
| --- | --- | --- |
| Append-only hash chain with tamper localisation | IMPLEMENTED | `tests/audit/chain.test.ts` |
| Signed, time-stamped checkpoints from a dedicated audit signer | IMPLEMENTED | `lib/pki/audit-checkpoints.ts`; OpenSSL verifies a checkpoint signature |
| Detection of a consistent rewrite and of truncation below a checkpoint | IMPLEMENTED | `tests/audit/checkpoints.test.ts`; Security Lab |
| Audit coverage of logins, documents, PKI, TSA, checkpoints, anchoring, exports and lab runs | IMPLEMENTED | Action list in `lib/audit/log.ts`; trail tests |
| Protection of entries after the latest checkpoint | PARTIAL | Hash chain only; stated as a limit and tested as one |
| Multi-process append safety | PARTIAL | In-process serialisation with a unique-constraint backstop; one application process assumed |

## 11. Blockchain anchoring and Merkle proofs

| Item | Status | Evidence |
| --- | --- | --- |
| RFC 6962 Merkle trees and RFC 9162 inclusion verification | IMPLEMENTED | Certificate Transparency test vectors (`tests/crypto/merkle.test.ts`) |
| Minimal owner-only anchor contract, reproducibly compiled | IMPLEMENTED | `contracts/OmniTrustAnchor.sol`; `npm run contract:compile -- --check` in CI |
| Anchoring of signatures and checkpoints; verification of commitment, root, proof, chain instance, contract code, block and leaf count | IMPLEMENTED | `tests/anchoring/anchoring.test.ts` against a real local chain |
| Only the root and leaf count reach the chain | IMPLEMENTED | Transaction input asserted to be 68 bytes with zero value |
| Persistence of anchors across chain restarts | NOT IMPLEMENTED | The development chain is in-memory; verification reports UNAVAILABLE |
| Public-chain anchoring with key custody | NOT IMPLEMENTED | Transactions use the local node's development account |

## 12. Security Lab

| Item | Status | Evidence |
| --- | --- | --- |
| 15 real attack scenarios, including an honest control | IMPLEMENTED | `tests/security-lab/security-lab.test.ts`: all HELD, three consecutive runs |
| Isolation: child process, per-run sandbox database, storage and key, deleted afterwards | IMPLEMENTED | Guard tests; full sandboxed run; E2E |
| Before/after evidence that application data is untouched | IMPLEMENTED | Record counts and audit head compared per run |
| Admin-only, one run at a time, audited | IMPLEMENTED | Route and service tests |

## 13. User interface

| Item | Status | Evidence |
| --- | --- | --- |
| Dashboard from live data | IMPLEMENTED | `tests/dashboard/overview.test.ts`; browser check |
| Verification screen with evidence chain, trust summary and ten steps | IMPLEMENTED | Browser check (Phase 9) |
| Certificate explorer: trust chain with fingerprints, X.509 fields, CRL-derived revocation, key lifecycle | IMPLEMENTED | `tests/pki/explorer.test.ts` checks fields against `node:crypto`'s parser |
| Algorithm comparison and crypto-agility page | IMPLEMENTED | Browser check |
| Audit timeline, anchoring view, Security Lab console, benchmarks with statistics | IMPLEMENTED | Browser checks (Phases 7–10) |
| Document versioning with per-version signature details | IMPLEMENTED | Document page |
| Design system: light, dark and system themes; semantic verdict colours; distinct colours for classical, post-quantum and hybrid algorithms | IMPLEMENTED | `app/globals.css`, `tailwind.config.ts`, `components/theme-toggle.tsx`; theme application checked in the browser (Phase 18) |
| Application shell: collapsible sidebar, breadcrumbs, Ctrl/⌘+K command palette, mobile navigation sheet | IMPLEMENTED | `components/app-shell.tsx`; palette, filtering and sidebar collapse checked through the DOM (Phase 18) |
| Migration-study results in the interface | IMPLEMENTED | Benchmarks page, read from `public/migration-study.json` |
| Responsive layout on narrow screens | PARTIAL | A mobile navigation sheet replaces the sidebar below the large breakpoint, but layouts have not been reviewed at phone widths |
| Formal accessibility audit | NOT IMPLEMENTED | Semantic labels and `aria-current` are used, but no audit was performed |

## 14. Benchmarks

| Item | Status | Evidence |
| --- | --- | --- |
| n, mean, median, sample SD, standard error, 95% t confidence interval, type-7 percentiles, CV, Tukey outliers | IMPLEMENTED | `lib/benchmarks/statistics.ts`, checked against hand computations |
| Recorded environment and methodology (Node, V8, OpenSSL, CPU, memory, git commit and dirty flag) | IMPLEMENTED | `public/benchmarks.json` (generated locally, gitignored) |
| Smoke mode for CI that never overwrites real results | IMPLEMENTED | Hash comparison in Phase 10; validated in `npm run ci` |
| Implementation-independent comparison of algorithms | LIMITED BY LIBRARY | Ed25519 runs in pure JavaScript while the others run in native OpenSSL, so its timings describe the library; stated on the page |
| Pairwise significance testing: Mann-Whitney U (primary), Welch's t, Holm correction, Cliff's delta, Hodges-Lehmann shift | IMPLEMENTED | `lib/benchmarks/inference.ts`, `lib/benchmarks/comparison.ts`; checked against closed forms (`tests/benchmarks/inference.test.ts`) |
| Post-quantum migration study across the trust chain (certificate, signature, CMS, time-stamp token, CRL growth, anchoring commitment; issuance, end-to-end sign and verify, CMS verification, orchestration overhead) | IMPLEMENTED | `npm run study:migration` in an isolated installation, with interleaved seeded rounds; results in `docs/upgrade-log.md` Phase 17 |
| Cross-machine reproducibility of timings | PARTIAL | The study records its environment and seed, but has been run on one machine only |

## 15. Testing

| Item | Status | Evidence |
| --- | --- | --- |
| Unit, integration and security suites | IMPLEMENTED | 699 passed, 1 skipped (end of Phase 14) |
| Route-level tests for every API route, with a coverage guard | IMPLEMENTED | `tests/api/routes.test.ts`, `route-coverage.test.ts` |
| Tests that failed before their fix, for each bug found in the upgrade | IMPLEMENTED | Recorded per bug in the upgrade log |
| Documentation drift guard (commands, seeded filenames, links) | IMPLEMENTED | `tests/ci/docs-claims.test.ts` |
| Code-coverage percentage measurement | NOT IMPLEMENTED | Coverage is argued per feature, not reported as a percentage |

## 16. Local CI and end-to-end regression

| Item | Status | Evidence |
| --- | --- | --- |
| `npm run ci`: 11 offline gates with a PASS/FAIL summary and a report | IMPLEMENTED | Full run passed in 237 s; failure path demonstrated |
| `npm run e2e`: isolated production installation driven over HTTP | IMPLEMENTED | 17/17; negative control fails exactly the anchoring step |
| Hosted CI | NOT IMPLEMENTED | Out of scope by the local-first rule |

## 17. Security audit

| Item | Status | Evidence |
| --- | --- | --- |
| Audit of auth, sessions, request hardening, routes, key handling, logging, PKI publication, sandboxing | IMPLEMENTED | [`docs/audit/02-security-audit.md`](audit/02-security-audit.md) |
| Findings S1–S4 fixed with failing-first tests | IMPLEMENTED | Encrypted private key in an API response; state-changing public GETs; first time-stamp race; not-yet-valid reported as expired |
| Finding S5 (stale README limitations) | IMPLEMENTED | README rewritten in Phase 15; guarded by the docs test |
| Offline dependency-advisory scanning | NOT IMPLEMENTED | `npm audit` needs the registry |

## 18. Bugs found and fixed during the upgrade

Each was found by a test, an external tool or a live check, not assumed.

1. A storage I/O failure was reported as `HASH_MISMATCH` (Phase 1).
2. RSA and ECDSA providers accepted each other's keys and signatures, so relabelled signatures verified (Phase 2).
3. CRL entries for top-bit serials were encoded as negative integers, so OpenSSL treated revoked certificates as valid (Phase 4a).
4. CRL PEM label rejected by OpenSSL (Phase 4a).
5. A failed migration was recorded as applied (Phase 5).
6. Automated OpenSSL checks were attributed to the wrong CLI version in the log (Phase 5 correction).
7. A fresh install's first time-stamp could predate its authority (Phase 10).
8. A not-yet-valid certificate was reported as expired (Phase 10).
9. `POST /api/certificates` returned the encrypted private key (Phase 11).
10. Unauthenticated GET routes created the TSA and issued CRLs (Phase 13).
11. The E2E script used a crypto primitive outside `lib/crypto`, caught by the project's own boundary check (Phase 14).

## 19. Not implemented, collected

- OCSP, delta CRLs, intermediate CAs, certificate renewal, an operator key-rotation workflow.
- HSM or KMS key custody; multi-factor authentication; server-side session revocation.
- ETSI EN 319 102-1, CAdES or PAdES conformance; PDF signing.
- Persistent or public-chain anchoring.
- Composite signatures other than ML-DSA-65 + ECDSA P-256 (the draft defines 18 combinations); composite certificate authorities (the CA still signs with a classical algorithm).
- Multi-instance deployment.
- Offline dependency-advisory scanning; code-coverage percentages; hosted CI.
- A formal accessibility audit.

## 20. Reproducing the evidence

```bash
npm install && npm run setup     # fresh installation with seeded, time-stamped samples
npm test                         # the test suite
npm run ci                       # every quality gate
npm run build && npm run e2e     # the full demo over HTTP against an isolated installation
npm run benchmark                # measurements on this machine
```

The guided demonstration is [`DEMO_SCRIPT.md`](../DEMO_SCRIPT.md). Per-phase evidence, including every negative result and correction, is in [`docs/upgrade-log.md`](upgrade-log.md).
