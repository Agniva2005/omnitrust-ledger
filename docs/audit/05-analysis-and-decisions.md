# Analysis of the Post-Phase-20 Reassessment, and What Was Done (Phases 21–25)

A response to [`04-post-phase20-reassessment.md`](04-post-phase20-reassessment.md):
- each recommendation checked against the code;
- recommendations of my own that the reassessment did not make;
- what was implemented and what was declined, with the reason.

Evidence for each phase is in [`docs/upgrade-log.md`](../upgrade-log.md).

---

## 1. Where the reassessment is right, and where the code says otherwise

**Right, and confirmed in the code:**
- **No enterprise hardening since `03`.** No time went to the enterprise track. Key custody was still a plaintext file (`lib/crypto/symmetric.ts` read base64 bytes directly).
- **Classical CA under a post-quantum signature.** The strongest algorithm, the composite, was certified by a classical ECDSA root: `lib/pki/policy.ts` fixed `CA_ALGORITHM = "ECDSA_P256"`.
- **Missing `LICENSE`.** There was no `LICENSE`, although the contract declares MIT.
- **Study numbers at risk.** The Phase 17 numbers existed only in the gitignored `public/migration-study.json`.
- **Threat model and Security Lab table unwritten.** The threat model was a pointer, and the Security Lab had no adversary model per scenario.

**Premise that no longer held:**
- **What it assumed.** The reassessment, like `outline.md`, took it as given that a post-quantum CA is "blocked because WebCrypto doesn't expose ML-DSA". It suggested bypassing `@peculiar/x509` with a hand-built signing path.
- **What a probe on this machine found.** Node 24.14's WebCrypto implements ML-DSA-44/65, flagged experimental. `@peculiar/x509` has an extensible algorithm registry, and only lacks the OID mapping. A probe produced the following, all signed through the library's normal generator:
  - an ML-DSA-65 self-signed root;
  - a certificate issued under it;
  - a CRL.
- **Independent check.** OpenSSL 3.5, through `node:crypto`'s `X509Certificate.verify`, verified the certificates, and a flipped byte was rejected.
- **Consequence.** The engineering cost was one algorithm mapping and a policy change, not a parallel X.509 encoder. No new cryptographic code was needed.

**Not adopted as written:**

| Recommendation | Decision | Reason |
| --- | --- | --- |
| Hosted CI (`.github/`), P0 | Declined | The project brief is local-first: no GitHub, cloud or paid services. `npm run ci` (11 offline gates) and `npm run e2e` remain the gates. A workflow file that is never run would be decoration. |
| Cloud KMS / HSM custody | Replaced by local equivalents | Passphrase wrapping and Windows DPAPI (Phase 24): the strongest custody available without external services. They are still labelled "not an HSM or KMS" everywhere. |
| Postgres migration, P1 | Declined for now | The brief requires zero external services. The schema stays Postgres-compatible; the migration is future work. |
| MFA, P1 | Deferred | Implementable locally with RFC 6238 on HMAC, but it changes the demo login flow and the E2E plan. It is lower leverage than the items below. |
| Intermediate CA / OCSP / rotation | Deferred, but unblocked | Once issuer algorithms are policy, an intermediate CA can be ML-DSA from day one, as `04` §4.1 asks. Not built in this pass. |
| Second machine | Not possible here | Only one machine is available. A second seed on the same machine was run as the documented fallback (`04` §3 item 4), and the report says it is not cross-machine evidence. |
| Systematic literature search | Partly done | The one paper flagged unread (arXiv 2511.00111) was read; see §3. A full recorded search across IEEE Xplore, ACM DL and IACR ePrint remains to be done and is not claimed. |

## 2. My own recommendations (beyond `04`)

1. **Make every trust service's algorithm a policy, not a constant.**
   - *Why:* this turns "the CA and TSA migrate" from future work into a measurable configuration, and keeps the crypto-agility boundary intact: the only file naming algorithms is still `policy.ts`.
   - *Implemented:* Phase 21.
2. **Measure precision and replication across runs, not only within a run.**
   - *Why:* a significance table from one run cannot show whether a difference survives a different measurement order. The Phase 17 block-design bug is exactly that failure.
   - *Implemented:* Phase 22, `npm run study:compare`.
3. **Commit evidence with digests.**
   - *Why:* numbers cited by the paper must not live only in gitignored files, and must not change silently.
   - *Implemented:* Phase 22, `docs/evidence/` and the manifest test.
4. **Tie each Security Lab scenario to an adversary capability.**
   - *Why:* state what is out of scope with its consequence, and generate the table from a real run, so the threat model cannot drift from the code.
   - *Implemented:* Phase 23.
5. **Test key custody as an attack, not only as a feature.**
   - *Implemented:* Phase 24, the `stolen-key-file` scenario.
6. **Keep polish and trust separate in status reporting (`04` §4.2).**
   - *How:* the dashboard now shows master-key custody honestly, flagging the default plaintext file as needing attention instead of implying protection.

## 3. The flagged-unread paper

Chen, *A Comparative Study of Hybrid Post-Quantum Cryptographic X.509 Certificate Schemes*, arXiv 2511.00111 v1. It is written in Chinese; the text was extracted from the arXiv PDF with pdfminer and read.

**What it covers:**
- **Schemes.** Composite, catalyst and chameleon certificates, with ML-DSA-44 + ECDSA P-256 as the example.
- **Comparison.** Certificate length, computation time and suitability as a transition scheme, graded "short/long" and "yes/no".
- **Conclusion.** It recommends composite for dual security and chameleon for the migration period.

**What it does not contain:**
- measured sizes or timings;
- CMS or document signing;
- time-stamps or CRLs.

**Consequences for the paper:**
- There is no numeric overlap with this project's measurements.
- It must still be cited for the qualitative scheme comparison.
- It must be cited for the point that a composite certificate cannot be verified by a verifier without post-quantum support, which bounds any migration claim made for composites here.

This is recorded in `docs/paper/outline.md`.

## 4. What changed, by phase

| Phase | What | Evidence |
| --- | --- | --- |
| 21 | Post-quantum trust services by policy: ML-DSA-65 CA, TSA and audit signer; composite TSA; migration study records and varies the trust-service algorithms | `tests/pki/pq-issuer.test.ts` (OpenSSL 3.5 cross-check) |
| 22 | Cross-run comparison and committed, digest-checked evidence; the Phase 17 and Phase 10 result files preserved | `tests/benchmarks/study-comparison.test.ts`, `tests/ci/evidence-manifest.test.ts` |
| 23 | Threat model with adversary capabilities; generated evaluation tables; adversary shown on each Security Lab card | `docs/threat-model.md`, `tests/security-lab/threat-model.test.ts` |
| 24 | Master-key custody: passphrase (scrypt + AES-256-GCM) and Windows DPAPI; `npm run key:custody`; `stolen-key-file` scenario; custody on the dashboard | `tests/crypto/key-custody.test.ts`, Security Lab |
| 25 | Evidence runs, `LICENSE`, architecture diagrams, this document | `docs/evidence/`, `docs/architecture.md` |

## 5. What is still true after this pass

- **Not enterprise-grade.** No MFA, no intermediate CA or OCSP, SQLite, a single process, and no HSM. Key custody improved from "plaintext file" to "protected local file", which is a real but bounded change.
- **The paper's related-work section is still unwritten.** One paper was read; the systematic search is not done.
- **Timings come from one machine.** Two seeds do not establish cross-machine reproducibility.
- **The post-quantum CA path depends on a Node API that Node itself marks experimental.**
