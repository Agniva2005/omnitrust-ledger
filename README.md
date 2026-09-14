# OmniTrust Ledger

A PKI-driven document management system with algorithm-agnostic, multi-algorithm digital signature orchestration. Documents are hashed and signed under **RSA-PSS 3072**, **ECDSA P-256**, **EdDSA Ed25519** or the post-quantum **ML-DSA-65**, all through one interface. Signatures are verified against X.509 certificates from a local Certificate Authority, time-stamped by a local RFC 3161 authority, checked against CA-signed revocation lists, exportable as standard CMS signatures, and recorded in a hash-chained audit log with signed checkpoints and optional anchoring on a local blockchain.

> ### Demo / Not for Production Use
>
> This is a demonstrator built to accompany a research report. The cryptography is real: every signature verifies, and you can check them with OpenSSL or an independent library yourself. The **operational security posture is not production-grade**. The CA, Time-Stamp Authority and chain are local and trusted by nothing outside this installation, and private keys are protected by a key in a local file. See [Limitations](#limitations--not-for-production-use). Do not use it to sign anything that matters.

---

## Quickstart

Requires **Node.js 24** (developed and tested on 24.14.0). ML-DSA-65 runs in the OpenSSL 3.5 that Node 24 bundles; older Node versions cannot generate or verify ML-DSA keys.

```bash
npm install
npm run setup
npm run dev
```

Then open <http://localhost:3000> and follow **[DEMO_SCRIPT.md](DEMO_SCRIPT.md)**.

`npm run setup` is idempotent. It:
- writes `.env` with a freshly generated `JWT_SECRET`;
- creates `storage/` and a 32-byte master encryption key;
- applies the database migrations;
- seeds the demo data through the real services: the CA, one certificate per algorithm plus an expired one, signed and time-stamped samples, an unsigned draft and a pre-tampered invoice.

Two optional extras:

```bash
npm run chain       # in a second terminal: a local chain for the Anchoring page
npm run benchmark   # measure this machine; the Benchmarks page shows nothing until you do
```

### Demo accounts

All four use the password `demo1234`.

| Email | Role | Can |
| --- | --- | --- |
| `admin@demo` | ADMIN | everything, including revocation, signed audit checkpoints, anchoring and the Security Lab |
| `signer@demo` | SIGNER | upload, sign, verify, issue certificates for itself |
| `verifier@demo` | VERIFIER | verify documents and the audit log; **cannot** sign |
| `viewer@demo` | VIEWER | read only; **cannot** upload, issue certificates or verify |

---

## What the demo shows, and how each claim is backed

| Claim | Where to see it | Evidence |
| --- | --- | --- |
| Algorithms can be added or swapped without touching other layers | Algorithms page; sign under five algorithms | `npm run check:boundary`; `tests/crypto/agility.test.ts` registers an extra ML-DSA-44 provider at test time |
| Tampering is detected | `invoice-tampered.txt` → Verify | SHA-256 recomputed from the bytes on disk; Security Lab document and ciphertext attacks |
| A signature's validity is judged at a trusted time | Revoke a certificate, re-verify | RFC 3161 time-stamps; timestamp-aware revocation policy; `tests/verification/timestamp-aware.test.ts` |
| Revocation is published, not just a database column | `/api/pki/crl`, the certificate explorer | CA-signed CRLs with reason codes; checked by `openssl crl` in tests |
| Signatures verify outside the application | Document page → CMS (.p7s) | `openssl cms -verify` for RSA-PSS and ECDSA; independent libraries for Ed25519 and ML-DSA |
| The audit log is tamper-evident, including against a consistent rewrite | Audit log → Verify log integrity | Hash chain plus signed, time-stamped checkpoints |
| Commitments can be anchored without putting data on a chain | Anchoring page | RFC 6962 Merkle roots on a local chain; only the root and leaf count are sent |
| The controls hold against real attacks | Security Lab; [`docs/threat-model.md`](docs/threat-model.md) | 16 scenarios run in disposable sandboxes, each tied to an adversary capability; `npm run lab:evaluate` records the results as evidence |
| The trust services themselves can migrate to post-quantum | Dashboard trust services, after setup with `PKI_CA_ALGORITHM=ML_DSA_65` | An ML-DSA-65 root CA, TSA and audit signer by installation policy; `tests/pki/pq-issuer.test.ts` cross-checks the certificates with OpenSSL 3.5 |
| Performance is measured, with its uncertainty | Benchmarks page | n, median, mean with 95% CI, SD, outliers, recorded environment |

---

## Architecture

Each layer depends only on the layers beneath it.

| Layer | Folder | Responsibility |
| --- | --- | --- |
| Presentation | `app/`, `components/` | Pages and API route handlers; no business logic |
| Authentication & Authorisation | `lib/auth/` | bcrypt, JWT session cookie, failed-login throttling, role-to-capability map |
| Document Management | `lib/documents/` | Upload, hashing, versioning, lifecycle, signing, verification, export |
| Cryptographic Orchestration | `lib/crypto/` | **The only place algorithm-specific code lives**: provider registry, four providers, hashing, Merkle trees |
| PKI | `lib/pki/` | Local CA, certificates, validation, CRLs, RFC 3161 TSA, CMS, revocation policy, audit checkpoints, certificate explorer |
| Anchoring | `lib/anchoring/` | Merkle batching and a minimal contract on a local chain |
| Secure Storage | `lib/documents/storage.ts` | AES-256-GCM blobs on disk; makes no cryptographic decisions |
| Audit & Monitoring | `lib/audit/` | Append-only hash-chained log and its integrity walk |
| Security Lab | `lib/security-lab/` | Attack scenarios, confined to disposable sandboxes |

### The boundary that matters

Adding an algorithm means one provider file and one registry entry. This is enforced, not assumed:

```bash
npm run check:boundary
```

It scans `app/ lib/ components/ prisma/ scripts/` outside `lib/crypto/`, and fails on:
- cryptographic imports (`@noble/*`, `node:crypto` primitives, `@peculiar/x509` outside the PKI layer);
- any algorithm identifier written as a literal. One policy file, which chooses the CA's algorithm, is allowlisted.

### Verification

Ten steps, each reporting PASS, FAIL, UNAVAILABLE or SKIPPED:
1. retrieve the document;
2. retrieve the signature;
3. retrieve the certificate;
4. verify the RFC 3161 time-stamp over the signature value (optional; proof of existence);
5. validate the certificate **at the proven signing time**: chain, profile, validity period;
6. evaluate revocation from the CA-signed CRL;
7. extract the key from the certificate and confirm its algorithm;
8. recompute SHA-256 from the stored bytes;
9. verify the signature;
10. compare the hashes.

Four verdicts are kept distinct, never collapsed into two:

| Verdict | Meaning | Reasons |
| --- | --- | --- |
| **VALID** (shown as AUTHENTIC) | every required check passed | — |
| **INVALID** | positive evidence against the document, signature, time-stamp or certificate | `CERTIFICATE_CHAIN_INVALID`, `CERTIFICATE_EXPIRED`, `CERTIFICATE_NOT_YET_VALID`, `CERTIFICATE_REVOKED`, `ALGORITHM_MISMATCH`, `HASH_MISMATCH`, `SIGNATURE_INVALID`, `TIMESTAMP_INVALID` |
| **UNVERIFIABLE** | evidence needed for a decision could not be obtained | `UNSUPPORTED_ALGORITHM`, `CERTIFICATE_NOT_FOUND`, `REVOCATION_STATUS_UNAVAILABLE`, `REVOKED_NO_PROOF_OF_EXISTENCE`, `EXPIRED_NO_PROOF_OF_EXISTENCE`, `STORAGE_UNAVAILABLE` |
| **ERROR** | the verifier itself failed | `INTERNAL_ERROR` |

### Revocation over time

Policy `omnitrust-timestamp-aware-revocation/1` (`lib/pki/revocation.ts`):
- A time-stamped signature survives a later revocation for a reason that does not imply key compromise, such as `affiliationChanged` or `superseded`.
- For `keyCompromise`, a signature survives only if it is proven to predate the recorded invalidity date.
- With no invalidity date the compromise time is unknown and the signature is INVALID. This is OmniTrust policy, stated as such, not an ETSI rule.
- With no time-stamp at all, a revoked or expired certificate makes the result UNVERIFIABLE rather than INVALID, following the "no proof of existence" indications of ETSI EN 319 102-1.

### Lifecycles

- **Document**: `created → uploaded → hashed → signed → stored → verified → versioned → archived | revoked`
- **Certificate**: `requested → active → expired | revoked`
- **Key** (NIST SP 800-57): `generated → active → rotated → revoked → retired`

---

## Cryptography

| Algorithm | Implementation | Details |
| --- | --- | --- |
| RSA-PSS 3072 | `node:crypto` (OpenSSL 3.5) | SHA-256, MGF1-SHA-256, 32-byte salt; randomised |
| ECDSA P-256 | `node:crypto` (OpenSSL 3.5) | SHA-256, DER signatures; randomised |
| EdDSA Ed25519 | `@noble/ed25519` | RFC 8032, deterministic, 64-byte signatures |
| ML-DSA-65 | `node:crypto` (OpenSSL 3.5) | FIPS 204, NIST PQ category 3, 3309-byte signatures; cross-checked against `@noble/post-quantum` |
| Hashing | `node:crypto` | SHA-256 (SHA-512 for EdDSA and ML-DSA CMS digests) |
| Certificates | `@peculiar/x509` | X.509 v3 under a local root CA: ECDSA P-256 by default, or ML-DSA-65 by installation policy (see below) |
| Time-stamps | local RFC 3161 TSA | CMS SignedData over TSTInfo with signingCertificateV2; verified by `openssl ts` in tests |
| Signature export | CMS / PKCS#7 (RFC 5652) | Detached, with its own time-stamp over the signature value; no CAdES conformance is claimed |
| At rest | `node:crypto` | AES-256-GCM for document blobs and private keys |

Nothing is hand-rolled. The stored signature covers the raw 32 bytes of the document's SHA-256, identically for all algorithms.

### Post-quantum trust services

Which algorithm the root CA, the Time-Stamp Authority and the audit signer use is installation policy (`lib/pki/policy.ts`), not code. Set it before the service is first created, for the CA before `npm run setup`:

```bash
PKI_CA_ALGORITHM=ML_DSA_65 PKI_TSA_ALGORITHM=ML_DSA_65 PKI_AUDIT_SIGNER_ALGORITHM=ML_DSA_65 npm run setup
```

The rules:
- **CA.** `PKI_CA_ALGORITHM` must be an algorithm that can sign X.509 certificates: RSA-PSS, ECDSA P-256, Ed25519 or ML-DSA-65.
- **TSA and audit signer.** They sign CMS, so they also accept the composite ML-DSA-65 + ECDSA P-256.
- **Binding.** An existing service keeps the algorithm recorded when it was created.

How it works, and its limits:
- **Signing path.** An ML-DSA-65 CA signs certificates and CRLs through Node 24's WebCrypto ML-DSA, which Node marks experimental and announces with a runtime warning.
- **Independent check.** The certificates carry the RFC 9881 identifier with absent parameters, and OpenSSL 3.5 (through `node:crypto`) verifies them in `tests/pki/pq-issuer.test.ts`.
- **Composite CA.** Not implemented: WebCrypto has no composite algorithm.
- **External CLI checks.** The OpenSSL 3.2 and 3.4 command-line tools cannot check anything a post-quantum CA signs, so `openssl cms -verify` against such an installation fails even for classical end-entity signatures.

`npm run study:migration -- --ca-algorithm ML_DSA_65 --tsa-algorithm ML_DSA_65` measures what that migration costs, and `npm run study:compare` puts runs side by side.

### Master-key custody

The master key encrypts every private key and document blob. `npm run setup` writes it as a plaintext file. `npm run key:custody` reports and changes how that file is stored, without changing the key, so everything stays readable:

```bash
npm run key:custody -- status
npm run key:custody -- protect --method dpapi --yes        # Windows: bound to the current Windows user
npm run key:custody -- protect --method passphrase --yes   # reads OMNITRUST_NEW_MASTER_PASSPHRASE
```

**Passphrase protection:**
- **How it wraps.** The key is wrapped with AES-256-GCM under an scrypt-derived key (N = 2^17), and the file header is authenticated.
- **Starting the app.** Start it with `OMNITRUST_MASTER_PASSPHRASE` set in the process environment. Do not put it in `.env`, which sits beside the key.

**Loss.** Losing the passphrase, or the Windows profile behind a DPAPI file, makes every key and document unreadable.

**What it protects against.** Either option protects a *copied* key file: the Security Lab's `stolen-key-file` scenario tests this. Neither is an HSM or KMS, and neither helps against someone who controls the running host.

### Verify without trusting this application

On a document page, download **CMS (.p7s)**, **Document** and the **CA certificate**, then run:

```bash
openssl cms -verify -binary -inform DER -in document.p7s -content document -CAfile ca.pem -out verified.bin
```

This works for RSA-PSS and ECDSA with the OpenSSL CLI; 3.2.4 and 3.4.0 were checked. Those CLIs cannot process Ed25519 or ML-DSA CMS signatures, so those are verified in the test suite with `node:crypto` and `@noble/post-quantum`. You can also export everything for a stored signature from the command line:

```bash
npm run export:signature -- audit-report-ed25519.txt
```

---

## Commands

| Command | Does |
| --- | --- |
| `npm run dev` | Development server on port 3000 |
| `npm run setup` | Generate `.env` and keys, migrate, seed. Idempotent |
| `npm test` | Full test suite |
| `npm run ci` | Every quality gate offline: dependencies, schema, contract artifact, lint, type-check, boundary, unit/integration/security tests, build, benchmark smoke run |
| `npm run e2e` | End-to-end regression against an isolated production installation (run `npm run build` first) |
| `npm run build` | Production build |
| `npm run benchmark` | Measure sign/verify/hash/key generation per algorithm; `-- --smoke` for a quick run |
| `npm run chain` | Local Hardhat chain for anchoring (in-memory; state is lost when it stops) |
| `npm run contract:compile` | Recompile the anchor contract; `-- --check` confirms the committed artifact |
| `npm run check:boundary` | Confirm no algorithm-specific code exists outside `lib/crypto/` |
| `npm run study:migration` | Measure the post-quantum migration across the trust chain in a throwaway installation; `-- --ca-algorithm <id> --tsa-algorithm <id>` migrates the trust services too |
| `npm run study:compare -- <a.json> <b.json>` | Compare study runs: precision, sizes, and whether significant differences replicate |
| `npm run lab:evaluate` | Run every Security Lab scenario in a sandbox; writes `docs/evidence/security-lab/evaluation.json` and the tables in `docs/threat-model.md` |
| `npm run evidence:manifest` | Regenerate the SHA-256 manifest of committed evidence under `docs/evidence/` |
| `npm run key:custody` | Show or change how the master key file is protected (plaintext, passphrase or Windows DPAPI) |
| `npm run export:signature -- <file>` | Export a stored signature, its CMS form and the certificates for external verification |
| `npm run db:seed` | Re-run the seed only |
| `npm run db:reset` | Delete and recreate the development database |

### Environment variables

Created by `npm run setup`; see `.env.example`.

| Variable | Purpose |
| --- | --- |
| `DATABASE_URL` | SQLite file, relative to `prisma/` |
| `JWT_SECRET` | Signs the session cookie; generated at setup |
| `MASTER_KEY_PATH` | AES-256-GCM key protecting private keys and blobs |
| `STORAGE_ROOT` | Where encrypted blobs live |
| `ANCHOR_RPC_URL` | Chain for anchoring; default `http://127.0.0.1:8545` |
| `SECURITY_LAB_ROOT` | Where Security Lab sandboxes are created; default `storage/lab` |
| `PKI_CA_ALGORITHM`, `PKI_TSA_ALGORITHM`, `PKI_AUDIT_SIGNER_ALGORITHM` | Optional: the trust services' algorithms, bound when each service is created; default `ECDSA_P256` |
| `OMNITRUST_MASTER_PASSPHRASE` | Only for a passphrase-protected master key; set in the process environment, not in `.env` |

---

## Testing and evidence

```bash
npm test        # about 700 tests
npm run ci      # every gate, with a PASS/FAIL summary
npm run e2e     # the whole demo over HTTP, against a throwaway installation
```

The tests exercise failure paths with real cryptography and real data, not mocks. Highlights:

- **Independent references:**
  - Ed25519 against the RFC 8032 test vector;
  - ECDSA against `@noble/curves`;
  - ML-DSA-65 against `@noble/post-quantum` from the same seed;
  - Merkle trees against the Certificate Transparency test vectors.
- **External tools:** `openssl` verifies raw signatures, CMS exports, CRLs and time-stamp tokens, and a checkpoint signature.
- **Every verification failure mode,** including algorithm confusion, key substitution, time-stamp swaps, forged CRLs and signatures proven to predate a revoked or not-yet-valid certificate.
- **Audit log attacks:** row edits, re-attribution and deletion; a consistent rewrite that fools the hash chain but not a signed checkpoint; truncation.
- **Every API route at the route level,** with a scan of every response body for key material; a coverage test fails if a route has no route-level test.
- **Security Lab scenarios** run for real, and an isolation guard refuses to let them touch non-sandbox data.
- **Supporting records:**
  - [`docs/upgrade-log.md`](docs/upgrade-log.md) records each upgrade phase, the evidence, and the bugs found along the way;
  - [`docs/audit/02-security-audit.md`](docs/audit/02-security-audit.md) is the security audit;
  - [`docs/final-implementation-report.md`](docs/final-implementation-report.md) states the implementation status of every feature.

---

## Limitations — not for production use

**PKI and trust**
- The root CA, Time-Stamp Authority and audit signer are **local and trusted by nothing outside this installation**.
- They can be post-quantum (ML-DSA-65), but the CA cannot be composite.
- A running installation cannot change its CA algorithm: migrating means a new installation.
- Revocation is published as CA-signed CRLs. There is **no OCSP**, no delta CRL, **no intermediate CA**, and no path-length or name-constraint enforcement beyond the root's basic constraints.
- Certificate renewal and an operator key-rotation workflow are **not implemented**; the key lifecycle states exist, but only issuance and revocation move keys between them.

**Keys and secrets**
- **Where private keys are held.** Private keys are encrypted with a master key in a **local file** (`storage/keys/master.key`), not an HSM or KMS.
- **Default protection.** By default that file is plaintext: anyone who can read the filesystem can read every private key. Its restrictive file mode is not enforced on Windows.
- **Optional protection.** `npm run key:custody` can wrap the file under a passphrase or Windows DPAPI. That protects a copied file, not a compromised running host.
- The four demo accounts share a password shown on the login page.

**Application security**
- Sessions are stateless JWTs: logout clears the cookie, but a stolen token stays valid for up to 8 hours.
- Failed-login throttling is in memory, per process. Its per-client key trusts `X-Forwarded-For`; the per-account limit is the one that cannot be sidestepped.
- The CSP allows `'unsafe-inline'` scripts, because the Next.js App Router emits inline bootstrap scripts.
- The session cookie is `secure` only in production builds.
- Authorisation is by role: every role, including VIEWER, can read and export every document.
- No multi-factor authentication.

**Integrity and anchoring**
- The audit log is tamper-evident, not tamper-proof. Entries after the latest checkpoint are protected by the hash chain alone. Deleting the newest checkpoint together with the entries it covers is detectable only through an anchor.
- The anchoring chain is **in-memory**: restarting it discards every anchor, and verification then reports UNAVAILABLE. Transactions come from its public development account; a public chain would need real key custody, which is not implemented. An anchor proves existence by a block on that chain instance, not identity.

**Operations**
- SQLite with a single application process; audit appends are serialised in-process.
- No backups, retention policy or disaster recovery.
- `npm audit` needs the npm registry and is not part of the offline CI. The advisories reviewed at the start of the upgrade were confined to build and test tooling; they have not been re-checked offline.

---

## Project layout

```
app/                    Pages and API routes (presentation only)
components/             UI components
contracts/              OmniTrustAnchor.sol (anchoring)
lib/
  auth/                 Sessions, throttling, role-to-capability map
  crypto/               THE ONLY PLACE ALGORITHM-SPECIFIC CODE LIVES (providers, registry, hashing, Merkle)
  documents/            Upload, storage, lifecycle, signing, verification, export
  pki/                  CA, certificates, validation, CRL, TSA, CMS, revocation policy, checkpoints, explorer
  audit/                Hash-chained log and integrity walk
  anchoring/            Chain client and Merkle batching
  security-lab/         Attack scenarios and sandboxing
  benchmarks/           Statistics
prisma/                 Schema, migrations, seed and fixtures
scripts/                setup, benchmark, ci, e2e, boundary check, contract compile, signature export
tests/                  Unit, integration and security suites
docs/                   Upgrade log, audits, final implementation report
storage/                Encrypted blobs, keys, test and CI output (gitignored)
```

[`PROGRESS.md`](PROGRESS.md) records the original build; [`docs/upgrade-log.md`](docs/upgrade-log.md) records the upgrade that followed it.
