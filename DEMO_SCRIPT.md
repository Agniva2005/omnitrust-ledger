# DEMO_SCRIPT.md

A literal 23-step walkthrough of OmniTrust Ledger. Each step gives what to do, what you should see, and what it demonstrates. It takes about 25 minutes at a comfortable pace.

## Before you start

Use a **fresh setup**. The revocation steps rely on the seeded signatures carrying trusted time-stamps, which `npm run setup` creates. Node.js 24 is required.

```bash
npm install
npm run setup
npm run benchmark      # optional, so step 22 has measurements
npm run dev
```

In a **second terminal**, for step 20:

```bash
npm run chain
```

Open <http://localhost:3000>. All demo accounts use the password `demo1234`.

The seed contains:
- the local root CA;
- one certificate per algorithm for `signer@demo`, plus one expired certificate;
- a signed and time-stamped sample per algorithm: `supply-agreement-rsa.txt`, `board-minutes-ecdsa-p256.txt`, `audit-report-ed25519.txt` and `service-contract-ml-dsa-65.txt`;
- the unsigned `draft-policy.md`;
- `invoice-tampered.txt`, which was signed and then altered on disk.

---

## Part A — What the system is (steps 1–4)

| # | Do this | You should see | Demonstrates |
| --- | --- | --- | --- |
| 1 | Open <http://localhost:3000> signed out | Four signature algorithms read from the provider registry, including **ML-DSA-65 (post-quantum)**, the layered architecture, and the "Demo / Not for Production Use" footer | Registry-driven design; honest security posture |
| 2 | Go to **/login**, click the **SIGNER** chip, click **Sign in** | The dashboard for `signer@demo`; its permissions include `document:sign` but not `certificate:revoke` | Role-to-capability authorisation |
| 3 | Read the dashboard | Live counts of documents, signatures (all time-stamped, all with a CMS export), certificates, audit entries, the root CA, the Time-Stamp Authority and the latest CRL, and recent verifications | Every figure comes from the database at request time |
| 4 | Open **Algorithms** | A comparison of all four algorithms (class, security level, key and signature sizes, determinism, measured medians if you ran the benchmark), with a card per algorithm and a **Crypto-agility** section | The registry, and how "add an algorithm" is tested |

## Part B — Documents, certificates and signing (steps 5–8)

| # | Do this | You should see | Demonstrates |
| --- | --- | --- | --- |
| 5 | **Documents** → **Upload document** → choose any small text file under **File** → **Upload** | The document page, state **HASHED** and a SHA-256. Check it yourself with `certutil -hashfile <file> SHA256` (Windows) or `sha256sum <file>` | Real hashing of the uploaded bytes; blobs stored encrypted |
| 6 | **Certificates** → in **Issue a certificate**, pick **ML-DSA-65 (post-quantum)** under **Algorithm** → **Issue certificate** | A new ACTIVE ML-DSA-65 certificate, issued by the ECDSA P-256 root CA | Key generation through the registry; a post-quantum key certified by a classical CA |
| 7 | Open your uploaded document → under **Signing certificate** choose the new ML-DSA-65 certificate → **Sign document** | A signature row: ML-DSA-65, **3309 bytes**, and its Export links | Signing through a certificate, never by naming an algorithm |
| 8 | Open the four seeded samples from **Documents** | Signature sizes of **384** (RSA-PSS), about **70** (ECDSA), **64** (Ed25519) and **3309** (ML-DSA-65) bytes | One workflow, four algorithms |

## Part C — Verification (steps 9–11)

| # | Do this | You should see | Demonstrates |
| --- | --- | --- | --- |
| 9 | Open `audit-report-ed25519.txt` → **Verify** → **Run verification** | **AUTHENTIC**, an evidence chain of six green links (Certificate, Revocation, Time-stamp, Key, Signature, Content), a trusted time from the TSA, and ten passing steps | The ten-step workflow, with the certificate judged at the proven signing time |
| 10 | Open `invoice-tampered.txt` → **Verify** → **Run verification** | **INVALID**, reason **HASH_MISMATCH**; the Signature and Content links are red (the signature is checked against the recomputed hash, so it fails too) while Certificate, Revocation, Time-stamp and Key stay green, and step 10 shows the signed and recomputed hashes side by side | The invoice was signed for 4,000 and altered on disk to 9,000 behind the application's back |
| 11 | Open `supply-agreement-rsa.txt` → in **Signatures** click **CMS (.p7s)** and **Document**, and from **Verify outside this app** download the **CA certificate** → run the `openssl cms -verify …` command shown there | `CMS Verification successful` from OpenSSL | The signature verifies without trusting this application |

## Part D — Certificates and revocation over time (steps 12–18)

| # | Do this | You should see | Demonstrates |
| --- | --- | --- | --- |
| 12 | **Sign out**, then sign in with the **ADMIN** chip | The admin dashboard; permissions now include `certificate:revoke`, `audit:checkpoint`, `anchor:create` and `lab:run` | Only an admin revokes, checkpoints, anchors or runs attacks |
| 13 | **Certificates** → click `signer@demo` on the **ECDSA P-256**, ACTIVE row | The certificate explorer: the trust chain with SHA-256 fingerprints and every check, the parsed X.509 fields, revocation **NOT REVOKED** from the CRL, and the key at **ACTIVE** in its lifecycle | What a certificate actually says, read from its bytes |
| 14 | Back on **Certificates**, on that ECDSA P-256 row click **Revoke** → set **Reason (RFC 5280)** to **affiliationChanged** → **Confirm revocation** | Status **REVOKED** | A revocation that does not imply key compromise |
| 15 | Open `board-minutes-ecdsa-p256.txt` → **Verify** → **Run verification** | Still **AUTHENTIC**, with a revocation of affiliationChanged and a policy decision of **SIGNED_BEFORE_REVOCATION** | A time-stamp proves the signature existed before the revocation, so history is not rewritten |
| 16 | **Certificates** → on the **RSA-PSS 3072**, ACTIVE row click **Revoke** → choose **keyCompromise**, leave the invalidity date empty (note the warning) → **Confirm revocation** | Status **REVOKED** | A compromise with no known compromise time |
| 17 | Open `supply-agreement-rsa.txt` → **Verify** → **Run verification** | **INVALID**, reason **CERTIFICATE_REVOKED**, policy decision **COMPROMISE_TIME_UNKNOWN**, and only the Revocation link red | Same kind of action, opposite answer: the key may have been compromised before the signature |
| 18 | Open the explorer for that RSA-PSS certificate, then open <http://localhost:3000/api/pki/crl?format=pem> | The explorer shows REVOKED from a numbered CRL with keyCompromise, and the key's lifecycle events (issued, ACTIVE, revoked, REVOKED). The CRL downloads: a CA-signed list anyone can check | Revocation is signed evidence, not just a database column |

## Part E — Integrity, anchoring and attacks (steps 19–21)

| # | Do this | You should see | Demonstrates |
| --- | --- | --- | --- |
| 19 | **Audit log** → **Verify log integrity** → **Create signed checkpoint** → **Verify log integrity** again | First **LOG VERIFIED**, with a note that no checkpoint exists yet; then **LOG VERIFIED** with **1 checkpoint agree**. The timeline shows every action of this demo | A hash chain plus a signed, time-stamped checkpoint of its head |
| 20 | **Anchoring** (requires `npm run chain`) → **Anchor N pending commitments** | Local chain **REACHABLE**, then a batch row with a Merkle root, leaf count, block and transaction | Signatures and the checkpoint reduced to commitments; only a Merkle root goes on chain |
| 21 | **Security Lab** → on **Rewrite the audit log and recompute every hash** click **Run attack** | **CONTROL HELD**: "Hash chain alone: fooled (verifies); with checkpoints: LOG_REWRITTEN", with the sandbox deleted and the application database unchanged | A real attack in a disposable sandbox, beating the chain but not the checkpoint |

## Part F — Measurement and evidence (steps 22–23)

| # | Do this | You should see | Demonstrates |
| --- | --- | --- | --- |
| 22 | **Benchmarks** | n = 200 per operation; median, mean with a 95% confidence interval, SD, CV, outliers, the environment and methodology, and the note that Ed25519 runs in pure JavaScript | Honest, reproducible measurement with its uncertainty |
| 23 | In a terminal: `npm run ci`, then `npm run build` and `npm run e2e` | `CI PASSED` with 11 steps, then `E2E PASSED` with 17 steps against an isolated installation, the development database fingerprint unchanged | Every claim above is tested, not only demonstrated |

---

## If something goes wrong

| Symptom | Fix |
| --- | --- |
| Step 15 shows UNVERIFIABLE / REVOKED_NO_PROOF_OF_EXISTENCE | The signatures were seeded before time-stamping existed. Stop the server, delete `prisma/dev.db` and `storage/`, run `npm run setup` again |
| Step 14 or 16 has no ACTIVE row for that algorithm | It was already revoked in an earlier run; use a fresh setup |
| Anchoring shows UNAVAILABLE | Start `npm run chain`. Restarting the chain discards earlier anchors, which then verify as UNAVAILABLE by design |
| Benchmarks page is empty | `npm run benchmark`, then reload |
| Login refused with "Too many failed sign-in attempts" | Wait 15 minutes, or restart the dev server (throttling is in memory) |
| Port 3000 is taken | `npm run dev -- -p 3001` |
