# OmniTrust Ledger

A PKI-driven document management system with algorithm-agnostic, multi-algorithm digital
signature orchestration. Documents are hashed, signed under **RSA-PSS**, **ECDSA P-256**
or **EdDSA Ed25519** through a single interface, and verified against X.509 certificates
issued by a local Certificate Authority — with every security-relevant action recorded in
a hash-chained audit log.

> ### Demo / Not for Production Use
>
> This is a demonstrator built to accompany a research report. The cryptography is real —
> every signature verifies, and you can check them with OpenSSL yourself — but the
> **operational security posture is not production-grade**. See
> [Limitations](#limitations--not-for-production-use) for the specifics. Do not use it to
> sign anything that matters.

---

## Quickstart

Requires Node.js 20 or newer (developed on 24.14).

```bash
npm install
npm run setup
npm run dev
```

Then open <http://localhost:3000> and follow **[DEMO_SCRIPT.md](DEMO_SCRIPT.md)** for a
guided walkthrough.

`npm run setup` is idempotent and does everything a fresh clone needs: writes `.env` with
a freshly generated `JWT_SECRET`, creates `storage/` and a 32-byte master encryption key,
applies the database migrations, and seeds the demo data.

### Demo accounts

All four use the password `demo1234`.

| Email | Role | Can |
| --- | --- | --- |
| `admin@demo` | ADMIN | everything, including revoking certificates and verifying the audit chain |
| `signer@demo` | SIGNER | upload, sign, verify, issue certificates for itself |
| `verifier@demo` | VERIFIER | verify documents and the audit chain; **cannot** sign |
| `viewer@demo` | VIEWER | read only; **cannot** upload or issue certificates |

---

## What the demo shows

| Claim | Where to see it | How it is enforced |
| --- | --- | --- |
| The algorithm can be swapped without touching other layers | Sign the same document flow under three algorithms | All algorithm-specific code lives in `/lib/crypto/`; `npm run check:boundary` fails the build if any escapes |
| Tampering is reliably detected | `invoice-tampered.txt` → Verify | SHA-256 recomputed from the bytes on disk at verification time, compared with the hash that was signed |
| Expiry and revocation are enforced | Revoke a certificate, then re-verify a document it signed | Certificate validation runs as step 4 of every verification |
| The audit log is tamper-evident | Audit log → Verify log integrity | `entryHash = SHA256(prevHash + entry)`, walked and recomputed |
| Performance across algorithms can be measured | `/benchmarks` | `npm run benchmark` measures on your machine; nothing is shipped pre-computed |

---

## Architecture

Seven layers, each depending only on the layers beneath it.

| Layer | Folder | Responsibility |
| --- | --- | --- |
| Presentation | `app/` | Pages and API route handlers. No business logic. |
| Authentication & Authorization | `lib/auth/` | Sessions (bcrypt + JWT in an httpOnly cookie) and a role-to-capability map |
| Document Management | `lib/documents/` | Upload, hashing, versioning, lifecycle, signing, verification |
| Cryptographic Orchestration | `lib/crypto/` | **The only place algorithm-specific code lives.** Provider registry + RSA/ECDSA/EdDSA implementations |
| PKI | `lib/pki/` | Local CA, certificate issuance/validation/revocation, key lifecycle |
| Secure Storage | `lib/documents/storage.ts` | Encrypted blobs on disk. Makes no cryptographic decisions; calls the layer above |
| Audit & Monitoring | `lib/audit/` | Append-only hash-chained log and its integrity checker |

### The boundary that matters

The central architectural claim is that **adding a fourth algorithm means one new
provider file and one line in the registry**, with no other file changing. That is
enforced mechanically rather than by convention:

```bash
npm run check:boundary
```

It scans `app/ lib/ components/ prisma/ scripts/` — excluding `lib/crypto/` — and fails
on any `@noble/*` import, any `@peculiar/x509` import outside the PKI layer, or any
`node:crypto` signature, cipher or digest primitive. The same check runs inside
`npm test`, and the checker itself is tested against probe files that must be flagged.

### Lifecycles

- **Document** (`lib/documents/lifecycle.ts`): `created → uploaded → hashed → signed → stored → verified → versioned → archived | revoked`
- **Certificate** (`lib/pki/keys.ts`): `requested → active → expired | revoked`
- **Key** (`lib/pki/keys.ts`, aligned to NIST SP 800-57): `generated → active → rotated → revoked → retired`

Each is an explicit transition table; an illegal transition throws rather than being
silently persisted.

### The verification workflow

Eight steps, executed in order, each reporting its own result so the UI can show exactly
which check failed:

1. Retrieve the document and its recorded hash
2. Retrieve the signature record
3. Retrieve the signing certificate
4. Validate the certificate — chain to the local CA, validity period, revocation
5. Extract the public key **from the certificate**, not from the key-pair record
6. Recompute SHA-256 from the bytes stored on disk right now
7. Verify the signature against that recomputed hash, with the algorithm resolved from the signature record
8. Compare the recomputed hash with the hash that was actually signed

The result is structured, not a boolean:

```ts
type VerificationResult = {
  outcome: "AUTHENTIC" | "INVALID";
  reason?: "HASH_MISMATCH" | "SIGNATURE_INVALID" | "CERTIFICATE_EXPIRED"
         | "CERTIFICATE_REVOKED" | "CERTIFICATE_CHAIN_INVALID";
  steps: { step: string; passed: boolean; detail?: string }[];
};
```

---

## Cryptography

| Algorithm | Implementation | Details |
| --- | --- | --- |
| RSA | `node:crypto` (OpenSSL) | RSASSA-PSS, 3072-bit modulus, SHA-256, digest-length salt |
| ECDSA | `node:crypto` (OpenSSL) | NIST P-256 with SHA-256, DER-encoded |
| EdDSA | `@noble/ed25519` | Ed25519 per RFC 8032, deterministic, 64-byte signatures |
| Hashing | `node:crypto` | SHA-256 |
| Certificates | `@peculiar/x509` over Node WebCrypto | X.509 v3, signed by the local root CA (ECDSA P-256) |
| At rest | `node:crypto` | AES-256-GCM for document blobs and private keys |

Nothing is hand-rolled. What gets signed is the raw 32 bytes of the document's SHA-256
digest, identically across all three algorithms.

### Verify a signature without trusting this application

```bash
npm run export:signature -- audit-report-ed25519.txt
```

This exports the plaintext, the signed digest, the raw signature, the certificate and the
extracted public key, then prints the exact `openssl` command for that algorithm. Running
it has OpenSSL confirm the signature independently, using the public key taken from the
stored certificate.

---

## Commands

| Command | Does |
| --- | --- |
| `npm run dev` | Start the development server |
| `npm run setup` | Generate `.env` and keys, migrate, seed. Idempotent |
| `npm test` | Full test suite (266 tests), including the crypto boundary check |
| `npm run build` | Production build with type checking |
| `npm run benchmark` | Measure sign/verify/hash/key-generation per algorithm; writes `public/benchmarks.json` |
| `npm run check:boundary` | Verify no algorithm-specific code exists outside `/lib/crypto/` |
| `npm run export:signature -- <file>` | Export a signature for external verification |
| `npm run db:seed` | Re-run the seed only |

### Environment variables

Created by `npm run setup`; documented in `.env.example`.

| Variable | Purpose |
| --- | --- |
| `DATABASE_URL` | SQLite file, relative to `prisma/` |
| `JWT_SECRET` | Signs the session cookie. Generated randomly at setup |
| `MASTER_KEY_PATH` | AES-256-GCM key used to encrypt private keys and blobs at rest |
| `STORAGE_ROOT` | Where encrypted document blobs live |

---

## Testing

```bash
npm test
```

The suite covers the security-relevant *failure* paths, not just the happy ones:

- Every provider against a flipped digest bit, a flipped signature bit, a truncated
  signature, the wrong key, and every cross-algorithm combination.
- Ed25519 against the **RFC 8032 Test 1 vector**, plus cross-signing with OpenSSL.
- ECDSA P-256 cross-validated against `@noble/curves`, a second independent
  implementation.
- All five required verification failure modes — `HASH_MISMATCH`,
  `CERTIFICATE_EXPIRED`, `CERTIFICATE_REVOKED`, `SIGNATURE_INVALID`, and cross-algorithm
  key substitution — against real cryptography with no mocking.
- Tamper detection at two layers: a raw byte flip caught by the AES-GCM tag, and validly
  re-encrypted substituted content caught by the hash comparison.
- Audit chain tampering, including an entry re-attributed to a different real user, a
  deleted entry, and an attacker who recomputes the entry hash but cannot fix the next
  entry's link.
- RBAC: a VERIFIER cannot sign, a VIEWER cannot upload or issue certificates, only an
  ADMIN can revoke.

---

## Limitations — not for production use

These are deliberate consequences of building a self-contained demonstrator. They are
listed so that nothing here is mistaken for a production security posture.

**PKI**

- The root CA is **self-signed and trusted by nothing outside this application**. It is
  created by the seed script and lives in the same SQLite database as everything else.
- There is **no CRL or OCSP**. Revocation is a status column, checked by this application
  only. Nothing outside it would ever learn a certificate had been revoked.
- There is no certificate chain beyond one level, no intermediate CAs, and no path-length
  or name-constraint enforcement past what the root's basic constraints declare.
- Certificate renewal is not implemented; issuing a new certificate is the only path.

**Key management**

- Private keys are encrypted with AES-256-GCM using a key stored in a **local file**
  (`storage/keys/master.key`), not an HSM or KMS. Anyone who can read the filesystem can
  read that key and therefore every private key.
- Key rotation and retirement exist as lifecycle states but have no operator workflow.

**Application security**

- **No rate limiting** anywhere, including on login. No account lockout, no CAPTCHA.
- No CSRF tokens. The session cookie is `SameSite=Lax`, which mitigates but does not
  eliminate cross-site request risks for the state-changing `POST` routes.
- Sessions cannot be revoked server-side before the JWT's 8-hour expiry.
- `secure` is only set on the session cookie in production builds, so the cookie is sent
  over plain HTTP in development.
- Passwords have no complexity or breach-check requirements, and the demo accounts share
  a well-known password that is printed on the login page.
- No multi-factor authentication.

**Data and operations**

- SQLite with a single application process. The audit log's append serialisation is
  **in-process**; running multiple instances against one database would need a
  database-level lock (the unique `seq` constraint would catch a conflict, but the retry
  strategy assumes a single writer).
- Document blobs are never deleted, and there is no retention or archival policy beyond
  the lifecycle states.
- No backups, no key escrow, no disaster recovery.
- The audit log is tamper-*evident*, not tamper-*proof*: someone with database access can
  still alter it, and the integrity check is what surfaces that they did. Nothing is
  replicated to external or append-only storage.

**Known dependency advisories**

`npm audit` reports findings in build and test tooling only — `@vitest/mocker`,
`deepmerge-ts` via the Prisma CLI, and a nested `postcss` inside Next 15's build
pipeline. None of them are in the application's request path, and every offered fix is a
major version upgrade that would break the pinned toolchain. They are listed here rather
than silently ignored.

---

## Project layout

```
app/                    Pages and API routes (presentation only)
components/             UI primitives (shadcn/ui, vendored)
lib/
  auth/                 Sessions and the role-to-capability map
  crypto/               THE ONLY PLACE ALGORITHM-SPECIFIC CODE LIVES
    providers/          rsa.ts, ecdsa.ts, eddsa.ts
    orchestrator.ts     Registry: add an algorithm here and nowhere else
  documents/            Upload, storage, lifecycle, signing, verification
  pki/                  CA, certificates, validation, key lifecycle
  audit/                Hash-chained log and its integrity checker
prisma/                 Schema, migrations, seed and fixtures
scripts/                setup, benchmark, boundary check, signature export
tests/                  Mirrors lib/: auth, crypto, pki, documents, verification, audit
storage/                Encrypted blobs and the master key (gitignored)
```

`PROGRESS.md` records what was built in each phase, what was verified and how, and the
reasoning behind every judgement call.
