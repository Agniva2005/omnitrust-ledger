# DEMO_SCRIPT.md

A literal click-through for presenting OmniTrust Ledger live. Every step lists the URL,
what to click, and what you should see. The right-hand note says which part of the
Review 1 report that step demonstrates.

**Before you start**, from a clean clone:

```bash
npm install
npm run setup
npm run dev
```

Then open <http://localhost:3000>. Total run time: about 10 minutes at a comfortable pace.

Demo accounts (all use password `demo1234`):

| Account | Role | Used for |
| --- | --- | --- |
| `signer@demo` | SIGNER | uploading and signing |
| `verifier@demo` | VERIFIER | verification, and showing what a VERIFIER may *not* do |
| `admin@demo` | ADMIN | revoking a certificate, audit integrity |
| `viewer@demo` | VIEWER | showing RBAC refusals |

The seed creates: a local root CA, one active certificate per algorithm for
`signer@demo`, one already-expired certificate, and five documents — one unsigned, three
signed under the three different algorithms, and one that has been tampered with after
signing.

---

## Part 1 — The architecture in one screen (1 min)

| # | Do this | You should see | Report reference |
| --- | --- | --- | --- |
| 1 | Go to <http://localhost:3000> while logged out | The seven-layer architecture list, each layer named | **Section 9, Figure 10** — the layered architecture |
| 2 | Point at the footer | "Demo / Not for Production Use", naming the self-signed CA and the local encryption key | Honest statement of the security posture |

Say: *every layer in that list is a real folder under `/lib`, and the boundary between
them is enforced by a test, not by convention.*

---

## Part 2 — Sign in and see role-based access (1 min)

| # | Do this | You should see | Report reference |
| --- | --- | --- | --- |
| 3 | Go to <http://localhost:3000/login>, click the **SIGNER** chip, click **Sign in** | The dashboard for `signer@demo` | **Section 9** — Authentication & Authorization layer |
| 4 | Read the capability badges | `document:upload`, `document:sign`, `document:verify`, `certificate:issue` — but **no** `certificate:revoke` | RBAC is a capability map, not scattered role checks |

---

## Part 3 — Upload: the document becomes a hash (2 min)

| # | Do this | You should see | Report reference |
| --- | --- | --- | --- |
| 5 | Go to **Documents** → **Upload document** | The upload form | **Figure 4** — document lifecycle |
| 6 | Choose any small text file and click **Upload** | The document detail page, status **HASHED**, and a full SHA-256 | `created → uploaded → hashed` |
| 7 | In a terminal, run `sha256sum <the file you uploaded>` | The same 64 hex characters shown on the page | The hash is real, computed from the file's bytes |

Say: *the app never stores the file in the clear — the blob on disk is AES-256-GCM
encrypted — but the hash is of the original content, and you can reproduce it yourself.*

---

## Part 4 — Certificates under three algorithms (2 min)

| # | Do this | You should see | Report reference |
| --- | --- | --- | --- |
| 8 | Go to **Certificates** | The local root CA, then one certificate each for RSA-PSS 3072, ECDSA P-256 and EdDSA Ed25519, all showing **valid** — plus one already expired | **Figure 6** — certificate lifecycle; **Section 9** PKI layer |
| 9 | In the **Issue a certificate** box, pick an algorithm and click **Issue certificate** | A new ACTIVE certificate appears within a second or two | Key generation → X.509 issuance, signed by the local CA |

Say: *the dropdown is populated from the orchestrator's registry. Adding a fourth
algorithm means one new provider file and one registry line — this page doesn't change.*

---

## Part 5 — Sign the same action three ways (2 min)

| # | Do this | You should see | Report reference |
| --- | --- | --- | --- |
| 10 | Open **Documents** → the file you uploaded in step 6 | The **Sign** card with a certificate picker | **Section 10** — methodology |
| 11 | Note that the picker lists *certificates*, not algorithms | Each option shows algorithm, serial and expiry | The certificate determines the key and the algorithm |
| 12 | Pick one and click **Sign document** | A signature row appears: algorithm, size in bytes, certificate serial, signer, timestamp | `hashed → signed → stored` |
| 13 | Open `supply-agreement-rsa.txt`, `board-minutes-ecdsa.txt` and `audit-report-ed25519.txt` in turn | Signature sizes of **384**, **~70** and **64** bytes respectively | The same operation under three algorithms |

Say: *384 bytes, about 70, and exactly 64. Same document flow, same code path above the
orchestrator — only the provider differs.*

---

## Part 6 — Verification: Figure 8 executing live (2 min)

This is the centrepiece.

| # | Do this | You should see | Report reference |
| --- | --- | --- | --- |
| 14 | On `audit-report-ed25519.txt`, click **Verify** | The verify page naming the algorithm and the hash that was signed | **Figure 8** — verification workflow |
| 15 | Click **Run verification** | A green **AUTHENTIC** badge and steps 1-8 all passing, with sub-steps under step 4 | All eight steps, each with its own result |
| 16 | Read step 5 aloud | "SubjectPublicKeyInfo extracted from the certificate, not from the key-pair record" | Verification depends on the presented certificate |
| 17 | Read step 6 and 8 aloud | The hash recomputed from the bytes on disk *right now*, and the comparison against the hash that was signed | Steps 6 and 8 |

---

## Part 7 — Tamper detection (1 min)

| # | Do this | You should see | Report reference |
| --- | --- | --- | --- |
| 18 | Go to **Documents** → `invoice-tampered.txt` → **Verify** → **Run verification** | A red **INVALID** badge with reason **HASH_MISMATCH** | **Figure 8**, failure path |
| 19 | Point out steps 1-6: all green | The certificate is fine, the blob decrypted cleanly | The document was altered, not the certificate |
| 20 | Point out step 8 | Two different hashes side by side: the signed one and the recomputed one | The comparison is what catches it |

Say: *this invoice was signed for 4,000 and the stored copy now says 9,000. The
alteration was made at the storage layer, behind the application's back, and
re-encrypted correctly — so the integrity check on the blob passes. It is the hash
comparison in step 8 that catches it.*

If someone asks "did you just hard-code that?": open a terminal and run
`npm run export:signature -- invoice-tampered.txt`. It prints the recorded hash and the
hash recomputed from the stored bytes, and they differ.

---

## Part 8 — Revocation changes the answer (1 min)

| # | Do this | You should see | Report reference |
| --- | --- | --- | --- |
| 21 | Verify `board-minutes-ecdsa.txt` first | **AUTHENTIC** | Baseline |
| 22 | Sign out, sign in as **admin@demo** | ADMIN dashboard, now including `certificate:revoke` | Section 6 — only ADMIN may revoke |
| 23 | Go to **Certificates**, find the ECDSA P-256 certificate for `signer@demo`, click **Revoke** → **Confirm** | Status **REVOKED**; its Validation column now reads `CERTIFICATE_REVOKED` | **Figure 6** — certificate revocation |
| 24 | Go back to `board-minutes-ecdsa.txt` → **Verify** → **Run verification** | **INVALID**, reason **CERTIFICATE_REVOKED** — the same document that passed a moment ago | Revocation is enforced at verification time |

Say: *nothing about the document or the signature changed. The cryptography is still
perfectly valid — step 7 still passes. What changed is the certificate's standing.*

---

## Part 9 — The expired certificate (30 sec, optional)

| # | Do this | You should see | Report reference |
| --- | --- | --- | --- |
| 25 | On **Certificates**, find the certificate expiring in 2024 | Status **EXPIRED**, validation `CERTIFICATE_EXPIRED` | **Figure 6** — expiry |

---

## Part 10 — The audit trail (1 min)

| # | Do this | You should see | Report reference |
| --- | --- | --- | --- |
| 26 | Go to **Audit log** (as admin@demo) | Every action from this demo in sequence: logins, uploads, signings, both verification outcomes with their reasons, the revocation | **Section 9** — Audit & Monitoring layer |
| 27 | Point at the `DOCUMENT_VERIFIED` rows | The metadata records `outcome` and `reason` for each | Both outcomes are audited, not just failures |
| 28 | Click **Verify log integrity** | **CHAIN INTACT**, with the number of entries checked | `entryHash = SHA256(prevHash + entry)` |

To show the chain actually detecting tampering, edit one row directly in the database —
the point being that this bypasses the application entirely:

```bash
npx prisma studio
```

Change the `metadataJson` of any audit entry, then click **Verify log integrity** again:
it reports **CHAIN BROKEN**, the sequence number of the altered entry, and
`ENTRY_HASH_MISMATCH`. (`npm run setup` will not undo this; re-seed from scratch if you
want a clean log afterwards.)

---

## Part 11 — Measured performance (1 min)

| # | Do this | You should see | Report reference |
| --- | --- | --- | --- |
| 29 | Go to **Benchmarks** | Sizes and timings measured on this machine, with the environment named | **Section 10** — comparative evaluation |
| 30 | Read the **IMPORTANT** note aloud | RSA and ECDSA run in OpenSSL native code; Ed25519 runs in pure JavaScript via `@noble/ed25519` | The timings compare implementations as much as algorithms |
| 31 | Point at the sizes table | Ed25519 signatures 64 bytes, ECDSA ~70, RSA 384 | Sizes *are* algorithm properties, unaffected by implementation |

If the page says "No measurements yet", run `npm run benchmark` and reload — nothing
ships with pre-computed numbers.

Say: *the honest headline is the caveat. Comparing a pure-JavaScript Ed25519 against
native RSA and ECDSA measures the libraries as much as the mathematics, and the page
says so rather than presenting a flattering number.*

---

## Part 12 — The claims are testable (1 min, optional but strong)

Run these in a terminal in front of the audience:

```bash
npm test
```

266 tests at the time of writing, including every failure mode shown above. Then:

```bash
npm run check:boundary
```

Confirms that no algorithm-specific import exists anywhere outside `/lib/crypto/` — the
architectural claim, enforced mechanically.

And to verify a signature **without trusting this application at all**:

```bash
npm run export:signature -- audit-report-ed25519.txt
```

It prints an `openssl` command. Run it: OpenSSL, using the public key extracted from the
stored certificate, independently confirms the signature.

---

## If something goes wrong mid-demo

| Symptom | Fix |
| --- | --- |
| Login fails | `npm run setup` again — it is idempotent and will not overwrite your `.env` or keys |
| A page shows a stale result | The verify and audit pages re-run on demand; click the button again |
| Benchmarks page is empty | `npm run benchmark`, then reload |
| You want a completely fresh state | Stop the server, delete `prisma/dev.db` and the `storage/` directory, then `npm run setup` |
| Port 3000 is taken | `npm run dev -- -p 3001` |
