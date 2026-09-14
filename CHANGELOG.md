# Changelog

All notable changes to OmniTrust Ledger. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Detailed, per-phase evidence (tests run, bugs found, negative results) is in [`docs/upgrade-log.md`](docs/upgrade-log.md); the status of every feature is in [`docs/final-implementation-report.md`](docs/final-implementation-report.md).

## [Unreleased]

### Added
- `docs/paper/outline.md`: a working outline for a systems and empirical paper. It maps every intended claim to existing evidence, lists the measurements still required (cross-machine runs, larger n, a post-quantum CA and TSA), and records which related work has been verified and which has not. Nothing in it is a submission-ready result.
- `docs/audit/03-enterprise-and-publication-readiness.md`: an external readiness assessment with separate enterprise and publication tracks. Phases 16–18 act on parts of it.

## Phase 19 — Interface audit by walkthrough (2026-09-14)

### Fixed
- Revoking a certificate opens a dialog. The inline form had clipped its labels and forced the table to scroll sideways.
- Breadcrumbs name documents and certificates instead of showing ID fragments.
- Distinguished names and hashes no longer break mid-word on the verification and explorer pages.
- The dashboard no longer truncates algorithm names, and its timestamps say UTC.
- The documents and algorithms tables fit at laptop width.

### Changed
- Rebuilt document detail and certificate explorer pages: summary tiles, copy buttons, export buttons and a lifecycle stepper.
- Card-based pickers for signing certificates and certificate algorithms, a drop-zone upload page, readable audit metadata, a verdict banner for the integrity check, and a Security Lab summary with filters; non-admins can see the scenario catalogue.
- Card titles are real headings for assistive technology.

### Added
- A "Signed with" column on the documents list.

## Phase 18 — Interface redesign (2026-09-14)

### Changed
- A design system:
  - light, dark and system themes;
  - a semantic colour language: success for VALID, destructive for INVALID and ERROR, warning for UNVERIFIABLE, plus info;
  - distinct colours for classical, post-quantum and hybrid algorithms.
- A collapsible sidebar shell with breadcrumbs, a Ctrl/⌘+K command palette and mobile navigation.
- Rebuilt landing, sign-in, dashboard, documents, verification, certificates and algorithms pages. The verification view now leads with the verdict.
- A shared page header on the audit log, anchoring, Security Lab and benchmarks pages. The benchmarks page shows the migration study.

### Fixed
- The sign-in page said three demo accounts share the password; there are four.

## Phase 17 — Post-quantum migration study (2026-09-14)

### Added
- `npm run study:migration`: measures what moving signatures from classical to post-quantum and hybrid algorithms costs across the trust chain, through the application's own services, in an isolated installation.
  - Sizes: certificate, signature, CMS, time-stamp token, CRL growth, anchoring commitment.
  - Timings: issuance, end-to-end signing and verification, CMS verification, orchestration overhead.
- Inferential statistics: Mann–Whitney U, Cliff's δ, the Hodges–Lehmann shift, Welch's t and Holm correction, tested against closed forms.

### Fixed
- The study's first design measured algorithms in contiguous blocks and produced order effects that could not be causal. Measurements now run in interleaved rounds shuffled by a seeded generator.
- The first normal-distribution approximation was imprecise in the tails. It was replaced by a series and continued-fraction implementation, checked against independent numerical integration.

## Phase 16 — Composite ML-DSA-65 + ECDSA P-256 (2026-09-14)

### Added
- A post-quantum/classical hybrid signature, `id-MLDSA65-ECDSA-P256-SHA512` from draft-ietf-lamps-pq-composite-sigs-19, as one provider and one registry line.
- It is verified against the draft's published test vectors, and each component of its CMS signatures is checked independently with `@noble/post-quantum` and `@noble/curves`.

## Walkthrough fixes (2026-09-14)

### Fixed
- Opening an ECDSA or Ed25519 document broke `next dev`: a Prisma `Bytes` value shared Node's Buffer pool, which the development renderer transferred.
- Signing out left the user on the dashboard.
- The dashboard counted a lapsed certificate as active.
- An honest signature intermittently verified as UNVERIFIABLE, because a CRL issued mid-verification was dated after the verification instant.

## Upgrade Phases 1–15 (2026-09-13 to 2026-09-14)

### Added
- A provider abstraction with machine-checked metadata, and ML-DSA-65 (FIPS 204).
- An RFC 3161 time-stamp authority, a timestamp-aware revocation policy, and CA-signed RFC 5280 CRLs.
- RFC 5652 CMS export verifiable with the OpenSSL command line.
- Signed, time-stamped audit checkpoints.
- RFC 6962 Merkle anchoring on a local chain.
- The Security Lab: real attacks in disposable sandboxes.
- A redesigned interface, including the certificate explorer, the evidence chain and the algorithm comparison.
- Statistical benchmarks.
- Route-level tests, `npm run ci` (11 offline gates), a security audit, and `npm run e2e` (17 steps against an isolated production build).

### Fixed
- A storage failure was reported as HASH_MISMATCH.
- Relabelled signatures verified across algorithms.
- Negative CRL serials.
- A key-material leak in `POST /api/certificates`.
- State-changing public GET routes.
- The first time-stamp predated its authority.
- A not-yet-valid certificate was reported as expired.
- The full list is in the final report, §18.

## Initial build — Phases 0–10

### Added
- The seven-layer architecture and session authentication with RBAC.
- Document management and lifecycle.
- RSA-PSS, ECDSA P-256 and Ed25519 through the signature orchestrator.
- The local PKI.
- The eight-step verification workflow.
- The hash-chained audit log.
- Benchmarks, seed data, the demo script and documentation.
