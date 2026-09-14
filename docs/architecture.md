# Architecture diagrams

Diagrams of the system as it is implemented, drawn from the code rather than from the original report's figures. They render on any Markdown viewer that supports Mermaid. File paths name where each element lives.

## Layers

Each layer depends only on the layers beneath it. The dashed box is the only place algorithm-specific code may appear; `npm run check:boundary` enforces it.

```mermaid
flowchart TB
  UI["Presentation<br/>app/, components/"]
  AUTH["Authentication and authorisation<br/>lib/auth/"]
  DOCS["Document management<br/>lib/documents/"]
  LAB["Security Lab<br/>lib/security-lab/"]
  subgraph CRYPTO["Cryptographic orchestration: lib/crypto/"]
    ORCH["orchestrator.ts + registry.ts"]
    PROV["providers/: RSA-PSS, ECDSA, Ed25519,<br/>ML-DSA-65, composite ML-DSA-65+ECDSA"]
    CUST["key-custody.ts: plaintext, passphrase, DPAPI"]
    ORCH --> PROV
  end
  PKI["PKI<br/>lib/pki/: CA, certificates, CRLs, TSA, CMS,<br/>revocation policy, checkpoints, policy.ts"]
  ANCHOR["Anchoring<br/>lib/anchoring/"]
  STORE["Secure storage<br/>lib/documents/storage.ts"]
  AUDIT["Audit and monitoring<br/>lib/audit/"]

  UI --> AUTH --> DOCS
  UI --> LAB
  DOCS --> PKI --> ORCH
  DOCS --> ORCH
  DOCS --> STORE --> CUST
  PKI --> CUST
  DOCS --> AUDIT
  PKI --> AUDIT
  ANCHOR --> ORCH
  LAB -. "sandbox only" .-> DOCS
```

## Trust chain and installation policy

Which algorithm each trust service signs with is installation policy (`lib/pki/policy.ts`), fixed when the service is created. The defaults are ECDSA P-256; a post-quantum CA is `PKI_CA_ALGORITHM=ML_DSA_65`.

```mermaid
flowchart LR
  POLICY["policy.ts<br/>PKI_CA_ALGORITHM<br/>PKI_TSA_ALGORITHM<br/>PKI_AUDIT_SIGNER_ALGORITHM"]
  CA["Root CA<br/>self-signed<br/>any x509Issuer algorithm"]
  EE["End-entity certificates<br/>every registered algorithm"]
  TSA["Time-Stamp Authority certificate<br/>critical id-kp-timeStamping"]
  AS["Audit signer certificate"]
  CRL["CRLs<br/>signed by the CA"]
  SIG["Document signature + CMS"]
  TST["RFC 3161 token"]
  CP["Signed audit checkpoint"]

  POLICY --> CA
  POLICY --> TSA
  POLICY --> AS
  CA --> EE
  CA --> TSA
  CA --> AS
  CA --> CRL
  EE --> SIG
  TSA --> TST
  TST --> SIG
  AS --> CP
  TST --> CP
```

## Verification and verdicts

Ten steps against the stored bytes. INVALID requires positive evidence; missing or unauthenticated evidence gives UNVERIFIABLE; a verifier fault gives ERROR. The four verdicts are never merged.

```mermaid
flowchart TD
  S1["1-3 Retrieve document,<br/>signature, certificate"] --> S4["4 Verify RFC 3161 time-stamp<br/>(proof of existence)"]
  S4 --> S5["5 Validate certificate at the<br/>proven signing time"]
  S5 --> S6["6 Revocation from the<br/>authenticated CRL"]
  S6 --> S7["7 Extract key, confirm algorithm<br/>from key material"]
  S7 --> S8["8 Recompute SHA-256<br/>from stored bytes"]
  S8 --> S9["9 Verify signature<br/>through the orchestrator"]
  S9 --> S10["10 Compare hashes"]
  S10 --> V{"Verdict"}
  V -->|"every required step PASS"| VALID["VALID"]
  V -->|"a step FAILs"| INVALID["INVALID + reason"]
  V -->|"evidence unavailable"| UNVER["UNVERIFIABLE + reason"]
  V -->|"verifier fault"| ERR["ERROR"]
```

## Evidence pipeline

How measured claims reach the paper without being retyped.

```mermaid
flowchart LR
  STUDY["npm run study:migration<br/>isolated installation,<br/>interleaved seeded rounds"] --> EVID["docs/evidence/*.json"]
  LABRUN["npm run lab:evaluate<br/>one sandbox per scenario"] --> EVID
  LABRUN --> TM["docs/threat-model.md<br/>generated tables"]
  EVID --> CMP["npm run study:compare<br/>precision and replication"]
  EVID --> MAN["npm run evidence:manifest<br/>SHA-256 per file"]
  MAN --> TEST["tests/ci/evidence-manifest.test.ts"]
```
