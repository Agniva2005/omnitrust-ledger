# OmniTrust Ledger — Re-Assessment After Phases 16–20 (2026-09-14)

A follow-up to `docs/audit/03-enterprise-and-publication-readiness.md`, performed the same way: reading the current code, `CHANGELOG.md`, `docs/final-implementation-report.md`, and the new `docs/paper/outline.md`, and diffing against what `03` saw. `03` is left as-is, as a record of what the project looked like before this work; this document supersedes it as the current roadmap.

---

## 1. What actually changed, in one paragraph

Since `03` was written, five real phases landed (16–20): a working **composite post-quantum/classical hybrid signature** (ML-DSA-65 + ECDSA P-256, per the IETF LAMPS draft, validated against the draft's own test vectors); a **post-quantum migration study** across the whole trust chain with proper non-parametric statistics (Mann–Whitney U, Cliff's δ, Hodges–Lehmann shift, Welch's t, Holm correction) that also *found and fixed its own methodological bug* (a block-design confound from measuring algorithms in contiguous batches); a genuine **verification-time consistency bug** found and fixed (a CRL issued mid-verification could post-date the verification instant and intermittently flip an honest signature to UNVERIFIABLE); a full **interface redesign** (design system, collapsible sidebar shell, command palette, keyboard shortcuts, desktop-first layout up to 1760px); and — most consequential for the publication goal — a genuinely careful **paper outline** (`docs/paper/outline.md`) that maps every claim to evidence, refuses to cite anything unread, and explicitly marks open questions as `[verify]` rather than assuming them.

That last item deserves to be said plainly: the discipline in `outline.md` — declining to claim a research gap exists after only two searches, declining to cite a paper whose PDF couldn't be text-extracted, stating "acceptance is not assumed" — is the kind of intellectual honesty that most drafts never show, and it is exactly what a peer reviewer looks for as a proxy for whether the rest of the paper can be trusted. This should be preserved, not streamlined away, when the outline becomes prose.

## 2. Scorecard against the previous roadmap

| `03` recommendation | Status now | Note |
| --- | --- | --- |
| Related-work section, threat model, baseline comparison, reproducibility framing (Track B, §3.2) | **In progress, well-scaffolded** | `outline.md` exists with a full evidence map; the related-work section itself is explicitly "To be written; none yet," and the threat-model section is a pointer, not a draft |
| Statistical rigor upgrades: significance testing, baseline comparison (§3.2.4) | **Done, and exceeded** | Mann-Whitney/Welch/Holm/Cliff's δ/Hodges-Lehmann is more rigorous than what was asked for; the block-design fix is itself now a paper contribution |
| Security Lab reframed as a systematic evaluation table (§3.2.5) | **Planned, not yet written** | `outline.md` §VI points at it but the table doesn't exist yet |
| Cross-machine benchmark run (§3.2.4) | **Not done** | `final-implementation-report.md` §14 now explicitly logs this as PARTIAL: "run on one machine only" |
| Architecture diagrams embedded in the repo (§4) | **Not done** | Still text/table-only; the twelve existing figures from the academic report still aren't in `README.md`/`docs/` |
| `LICENSE` file (§4) | **Not done** | Still no top-level `LICENSE`, though the contract still declares `SPDX-License-Identifier: MIT` |
| Recorded demo walkthrough (§4) | **Not done** | `DEMO_SCRIPT.md` was updated for the new UI but no recording exists |
| Master key out of a plain file — KMS/HSM/OS keystore (Track A, P0) | **Not started** | Still `storage/keys/master.key`; untouched by Phases 16–20 |
| Hosted CI pipeline (Track A, P0) | **Not started** | No `.github/` directory exists at all |
| MFA (Track A, P1) | **Not started** | — |
| Intermediate CA + OCSP + key rotation (Track A, P1) | **Not started**, and now slightly *behind*: the new composite algorithm adds a certificate type the current single-CA model can't issue with the strongest algorithm it now supports (the CA still signs everything with classical ECDSA — noted honestly in `final-implementation-report.md` §19) | See §4.1 below |
| Postgres migration (Track A, P1) | **Not started** | — |
| CHANGELOG / project hygiene (§4) | **Done** | `CHANGELOG.md` added, Keep-a-Changelog format, exactly as recommended |

Reading straight across: **every hour since `03` went to the publication track and the UI**, and **zero hours went to the enterprise track**. That's a legitimate and coherent choice — a paper and a polished demo reinforce each other, and production hardening doesn't help either — but it means the honest answer to "is this closer to enterprise-grade" is currently **no**, while the honest answer to "is this closer to journal-worthy" is **yes, meaningfully**. The recommendations below reflect that asymmetry rather than repeating a balanced 50/50 list.

---

## 3. Updated recommendations — Journal track (the higher-leverage work right now)

The project is now materially closer to a genuine, defensible contribution than it was at `03`. The composite ML-DSA implementation plus the whole-trust-chain migration study plus the block-design finding is a real, three-legged contribution, not just "we built a system." What's left is almost entirely writing and verification discipline, not engineering:

1. **Finish the related-work section — this is now the single largest remaining gap.** `outline.md` §III is empty and §"Verified so far" shows real, careful progress (several PQ-in-TLS papers checked, one paper explicitly flagged as unread and un-citable) but also several `[verify]` items still unresolved, including the foundational NIST FIPS references and the crypto-agility literature. Do not let the strength of the engineering carry the paper past a thin related-work section — that is the single most common reason a technically sound systems paper gets rejected. Budget real time for a systematic search (IEEE Xplore, ACM DL, IACR ePrint, Google Scholar, with the queries recorded, exactly as `outline.md` already promises) before claiming any gap.

2. **Read arXiv 2511.00111 before making any certificate-size comparison.** `outline.md` already flags this correctly — the PDF wouldn't text-extract and the paper is "not yet read." Don't let this quietly become "assumed not overlapping." If it can't be read as a PDF, try HTML-through-ar5iv, or reach out for the text directly; a reviewer who has read it and finds an uncredited overlap will not be lenient.

3. **Write the formal threat model (outline §VI) before writing results.** The ingredients exist across the Security Lab catalogue and this project's own prior audit, but the paper needs the explicit table this document already recommended: adversary capability → mechanism relied on → scenario that tests it → result. This is a few hours of restructuring, and it should be written *before* the evaluation section, because the evaluation section's job is to satisfy the threat model, not the reverse.

4. **Get at least one more machine's numbers before writing the results section.** This is now the clearest concrete blocker in `final-implementation-report.md` (§14, marked PARTIAL for exactly this reason). A different CPU vendor if at all possible; a second seed on the same machine is the minimum fallback if a second machine genuinely isn't available.

5. **Resolve the CA/TSA migration measurement, or scope it out explicitly.** `outline.md` correctly identifies that measuring "what happens when the CA and TSA themselves migrate to post-quantum or composite" is the natural extension of contribution 1, and correctly notes it's blocked because `@peculiar/x509` is WebCrypto-based and WebCrypto doesn't expose ML-DSA or composite signing. Two honest paths: (a) treat this explicitly as future work and say so in the paper (the limitations section already has the right instinct for this kind of honesty), or (b) if it's worth the engineering time, the CA-signing path could plausibly move to `node:crypto` directly for this one case, mirroring exactly how the composite provider itself already bypasses WebCrypto (`lib/crypto/providers/composite-mldsa65-ecdsa-p256.ts` uses `node:crypto` throughout, not `@peculiar/x509`). Don't attempt this as a rushed addition right before a deadline — decide now which path this is.

6. **Reframe the Security Lab as the evaluation section's centerpiece (outline §VI/§VII boundary).** This was recommended in `03` and remains undone. It's still the fastest way to turn fifteen "HELD" results into a real evaluation table with a stated adversary model attached to each row.

7. **Increase end-to-end n and report achieved CI widths, as `outline.md` §"Measurements still required" already commits to.** This is scoped and the statistics code (`lib/benchmarks/inference.ts`, `lib/benchmarks/comparison.ts`) is already built for it — it's a re-run, not new engineering.

8. **Decide on an artifact-evaluation badge submission now, not after the paper is written.** `npm run setup / ci / e2e / study:migration` all work from a clean clone with a recorded environment and seed — this project is unusually well-positioned for an Available/Functional/Reproduced badge wherever the target venue offers one, and knowing this is the goal shapes how the artifact section gets written.

Net assessment for this track: **the venue guidance from `03` §3.1 should be revisited upward slightly, not downward.** A composite-signature implementation validated against IETF draft vectors, plus a properly-powered workflow-level PQ migration study, plus a genuine methodological finding (the block-design confound) is a more substantial three-part contribution than what `03` was written against. IEEE Access remains the right primary target and is now a stronger fit than before; a SecDev-style systems track remains the sound fallback. The one thing that has *not* changed is the honest scoping: this is still not a TDSC/TIFS "new cryptography" paper, and `outline.md` says so correctly — keep saying so.

---

## 4. Updated recommendations — Enterprise track (unchanged in substance, more urgent in one place)

Because no time went here since `03`, the priority list from that document still applies almost unchanged (§2.7 of `03`). Two things are worth adding given what actually shipped:

### 4.1 The new composite algorithm sharpens, not just adds to, the PKI-maturity gap

`final-implementation-report.md` §19 now states plainly: "composite certificate authorities (the CA still signs with a classical algorithm)." That means the system's strongest, most future-proof signature algorithm is currently certified by its weakest link — a classical ECDSA root CA. This was true in spirit before (the CA was always classical-only), but it is now a concrete, citable inconsistency between "our strongest algorithm" and "what vouches for it." When the intermediate-CA work from `03` §2.1 happens, it should be designed to support a composite- or ML-DSA-signed issuing CA from the start, not classical-only again — otherwise this gap just gets rebuilt one layer down.

### 4.2 The UI overhaul is a real, valuable asset for the enterprise pitch too — but it isn't a substitute for the P0 items

The design system, command palette, and desktop-first layout genuinely help the "does this feel professional" question from `03` §4, and should be credited as real progress on that front. But polish is orthogonal to trust: a beautifully designed system whose master key still lives in a plaintext file on disk is not closer to something an enterprise would route real signatures through. Keep these separate in status reporting — it would be easy, looking at how much visibly changed, to feel like broad progress was made toward "enterprise-grade" when in fact the specific things that phrase depends on (key custody, CI/CD, MFA, a real database) haven't moved.

### 4.3 Everything else from `03` §2 stands unchanged

Master key custody (P0), hosted CI (P0), MFA (P1), intermediate CA/OCSP/key rotation (P1, see 4.1), Postgres migration (P1), dependency scanning / observability / backup-DR runbook (P2), ownership-based authorization / distributed rate limiting (P2), persistent or public anchoring / containerization (P3). None of these have code-level prerequisites from the last five phases that need to be redone — the enterprise track can start from exactly where `03` left it.

---

## 5. Two small, concrete new findings from this pass

- **`.gitignore` now excludes `public/migration-study.json`** alongside `public/benchmarks.json`, which is correct and consistent (generated, environment-specific evidence shouldn't be committed) — but it means the migration-study numbers currently backing `docs/upgrade-log.md` Phase 17 and the paper outline exist only on this one machine. Before the "second machine" measurement in §3 item 4 above, make sure at least one full `migration-study.json` snapshot is preserved somewhere durable (attached to the phase's evidence in the upgrade log, or committed under a different, clearly-labeled path) so the first machine's numbers aren't lost if this machine's `storage/`/`public/` gets reset.
- **Still no `.github/` directory and no `LICENSE` file.** Both were flagged in `03` §4 as near-zero-effort wins; both remain open five phases later. Given how much other polish landed (CHANGELOG, design system, keyboard shortcuts), these two are now the most conspicuous "still missing" items for anyone skimming the repository's root — they're worth ten minutes each.

---

## 6. Suggested next phases, updated

Continuing the numbering from `CHANGELOG.md` (currently at Phase 20):

**Phase 21 — Related work and threat model.** Close out `outline.md` §III and §VI: the systematic literature search, the adversary-capability table, and reading the one flagged-unread paper. No code changes.

**Phase 22 — Second-machine evaluation.** Re-run `npm run study:migration` on a second machine/seed per `outline.md`'s own checklist, preserve both raw result files, increase end-to-end n, and report achieved CI widths.

**Phase 23 — Paper draft.** Turn `outline.md` into prose against the section plan already written, with the Security Lab table (§3.2.5/§6 above) as the evaluation centerpiece.

**Phase 24 — Enterprise foundations (can run in parallel with 21–23).** The unchanged P0 items from `03` §2.7: hosted CI first (cheapest, highest-visibility), then master-key custody. If the intermediate-CA work starts here, design it composite/ML-DSA-capable from day one per §4.1.

---

## 7. Closing assessment

This is a rare case where "keep going the same way" is close to the right advice. The last five phases did not chase breadth — they picked the one track (publication) and pushed it further than the previous assessment asked for, while also being honest, in the project's own new documents, about exactly what still isn't measured, isn't cited, and isn't implemented. The remaining publication work is now mostly writing and verification, not engineering, and is genuinely close. The enterprise track hasn't moved and shouldn't be expected to have — it wasn't where the effort went — but it also hasn't gotten harder to start; picking up hosted CI and key custody next, in parallel with finishing the paper, is a reasonable way to make progress on both fronts without either blocking the other.
