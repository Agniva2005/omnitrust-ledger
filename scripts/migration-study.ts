// Post-quantum migration study: what moving document signatures from classical to post-quantum and
// hybrid algorithms costs across the whole trust chain, measured through the real services.
//
//   npm run study:migration [-- --iterations 30 --micro-iterations 200 --warmup 3 --seed 20260914 --output <file>]
//
// The parent process builds a throwaway installation under storage/migration-study/<run id> (its own
// SQLite database, document storage, master key and JWT secret), migrates it, and runs this file
// again as a worker with that environment, so every service binds to the isolated database. The
// development database is fingerprinted before and after. The run directory is deleted afterwards
// and the results, including every raw timing sample, go to public/migration-study.json
// (gitignored: a clone never ships someone else's numbers as its own).
//
// Per registered algorithm, from operations actually performed:
// - sizes: SubjectPublicKeyInfo, certificate (DER), signature value, CMS SignedData, RFC 3161
//   token, the anchoring commitment, and the growth of the CA's CRL per revoked certificate;
// - timings: certificate issuance (key generation included), end-to-end signing (hash, signature,
//   two time-stamps, CMS, storage and audit), ten-step verification, standalone CMS verification,
//   and orchestrator sign/verify against a direct provider call (the crypto-agility overhead);
// - statistics: summaries per operation and Holm-corrected pairwise comparisons between algorithms.
//
// Measurement design. A first version measured each algorithm in one contiguous block and produced
// effects that cannot be causal (a composite whose CMS verification looked faster than that of its own
// ML-DSA component, an orchestrator faster than the provider it calls), which is the signature of
// drift and ordering bias. Every timed operation therefore runs in interleaved rounds: each round
// visits every algorithm once in an order freshly shuffled by a seeded generator, and paired
// orchestrator/provider measurements alternate which goes first. Documents to sign are uploaded
// before timing starts. The seed is recorded so a run's order can be reproduced.
//
// Algorithm identifiers are never written here: everything is derived from the registry.
import { execFileSync, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { sha256Hex } from "../lib/crypto/hash";

export const MIGRATION_STUDY_SCHEMA_VERSION = 2;

const ROOT = process.cwd();
const NODE = process.execPath;
const WORKER_FLAG = "--worker";
const STUDY_ROOT = path.join(ROOT, "storage", "migration-study");

function numericArg(flag: string, fallback: number): number {
  const index = process.argv.indexOf(flag);
  if (index === -1) return fallback;
  const value = Number(process.argv[index + 1]);
  return Number.isFinite(value) && value > 0 ? Math.floor(value) : fallback;
}

function stringArg(flag: string): string | null {
  const index = process.argv.indexOf(flag);
  return index === -1 ? null : process.argv[index + 1] ?? null;
}

const ITERATIONS = numericArg("--iterations", 30);
const MICRO_ITERATIONS = numericArg("--micro-iterations", 200);
const WARMUP = numericArg("--warmup", 3);
const SEED = numericArg("--seed", 20260914);

const sqliteUrl = (file: string) => `file:${file.split(path.sep).join("/")}`;

/** Mulberry32: a small, fast, seedable generator. Used only to order measurements, never for security. */
export function seededRandom(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** A shuffled copy (Fisher-Yates) driven by the given generator. */
export function shuffled<T>(items: readonly T[], random: () => number): T[] {
  const copy = [...items];
  for (let index = copy.length - 1; index > 0; index -= 1) {
    const other = Math.floor(random() * (index + 1));
    [copy[index], copy[other]] = [copy[other], copy[index]];
  }
  return copy;
}

function git(args: string[]): string | null {
  try {
    return execFileSync("git", args, { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  } catch {
    return null;
  }
}

function environment() {
  const cpus = os.cpus();
  const status = git(["status", "--porcelain"]);
  return {
    node: process.version,
    v8: process.versions.v8,
    openssl: process.versions.openssl,
    platform: `${os.platform()} ${os.release()}`,
    arch: os.arch(),
    cpu: cpus[0]?.model?.trim() ?? "unknown",
    cores: cpus.length,
    memoryGB: Math.round(os.totalmem() / 1024 ** 3),
    gitCommit: git(["rev-parse", "--short", "HEAD"]),
    gitTreeDirty: status === null ? null : status.length > 0,
  };
}

// ---------------------------------------------------------------------------------------------
// Worker: runs inside the isolated installation
// ---------------------------------------------------------------------------------------------

type SizeRange = { min: number; median: number; max: number };

async function worker(resultFile: string) {
  const { prisma } = await import("../lib/db");
  const { seedUsers } = await import("../prisma/fixtures");
  const { ensureRootCa } = await import("../lib/pki/ca");
  const { issueCertificate, revokeCertificate } = await import("../lib/pki/certificates");
  const { issueCrl } = await import("../lib/pki/crl");
  const { uploadDocument } = await import("../lib/documents/service");
  const { signDocument } = await import("../lib/documents/signing");
  const { verifyDocument } = await import("../lib/documents/verification");
  const { verifyDetachedSignature } = await import("../lib/pki/cms-signature");
  const { commitmentFor } = await import("../lib/anchoring/service");
  const { ALGORITHMS, orchestrator, providerFor } = await import("../lib/crypto/orchestrator");
  const { sha256 } = await import("../lib/crypto/hash");
  const { pemBody } = await import("../lib/crypto/pem");
  const { summarise, median } = await import("../lib/benchmarks/statistics");
  const { pairwiseComparisons } = await import("../lib/benchmarks/comparison");
  type Algorithm = (typeof ALGORITHMS)[number];

  await seedUsers();
  await ensureRootCa();
  const users = await prisma.user.findMany();
  const actor = (email: string, role: "ADMIN" | "SIGNER" | "VERIFIER") => {
    const user = users.find((candidate) => candidate.email === email);
    if (!user) throw new Error(`seeded user ${email} is missing`);
    return { userId: user.id, email: user.email, role };
  };
  const signer = actor("signer@demo", "SIGNER");
  const verifier = actor("verifier@demo", "VERIFIER");
  const admin = actor("admin@demo", "ADMIN");

  const random = seededRandom(SEED);
  const range = (values: number[]): SizeRange => ({ min: Math.min(...values), median: median(values), max: Math.max(...values) });
  const round4 = (values: number[]) => values.map((value) => Math.round(value * 10_000) / 10_000);
  const time = async (operation: () => Promise<unknown>) => {
    const start = process.hrtime.bigint();
    await operation();
    return Number(process.hrtime.bigint() - start) / 1_000_000;
  };

  const OPERATIONS = ["certificateIssuance", "signDocument", "verifyDocument", "cmsVerify", "orchestratorSign", "providerSign", "orchestratorVerify", "providerVerify"] as const;
  type Operation = (typeof OPERATIONS)[number];
  const samples = Object.fromEntries(OPERATIONS.map((operation) => [operation, Object.fromEntries(ALGORITHMS.map((algorithm) => [algorithm, [] as number[]]))])) as Record<Operation, Record<Algorithm, number[]>>;
  const rounds: Record<string, number> = {};

  /** Runs warm-up plus measured rounds; each round visits every algorithm once in a freshly shuffled order. */
  async function interleaved(name: string, measuredRounds: number, visit: (algorithm: Algorithm, measured: boolean, round: number) => Promise<void>) {
    const total = WARMUP + measuredRounds;
    for (let round = 0; round < total; round += 1) {
      for (const algorithm of shuffled(ALGORITHMS, random)) await visit(algorithm, round >= WARMUP, round);
    }
    rounds[name] = measuredRounds;
  }

  // --- Setup, untimed: a signing certificate, documents to sign, and primitive keys per algorithm ---
  console.log("Setting up certificates, documents and keys...");
  const setup = {} as Record<Algorithm, { certificateId: string; publicKeySpkiBytes: number; certificateDerBytes: number; queue: { id: string; bytes: Buffer }[]; signed: { documentId: string; bytes: Buffer }[]; keys: { publicKeyPem: string; privateKeyPem: string }; signature: Buffer }>;
  const message = sha256(Buffer.alloc(1024, 0x5a));
  for (const algorithm of ALGORITHMS) {
    const certificate = await issueCertificate({ actor: signer, algorithm });
    const queue = [];
    for (let index = 0; index < WARMUP + ITERATIONS; index += 1) {
      const bytes = Buffer.from(`Migration study ${algorithm} ${index} ${randomBytes(8).toString("hex")}\n${"x".repeat(1024)}`);
      const document = await uploadDocument({ actor: signer, filename: `study-${index}.txt`, mimeType: "text/plain", bytes });
      queue.push({ id: document.id, bytes });
    }
    const keys = await orchestrator.generateKeyPair(algorithm);
    setup[algorithm] = {
      certificateId: certificate.id,
      publicKeySpkiBytes: pemBody(certificate.keyPair.publicKeyPem).length,
      certificateDerBytes: pemBody(certificate.certPem).length,
      queue,
      signed: [],
      keys,
      signature: await providerFor(algorithm).sign(message, keys.privateKeyPem),
    };
  }

  // --- Timed phases, interleaved across algorithms ---
  console.log("Certificate issuance...");
  await interleaved("certificateIssuance", Math.max(10, Math.floor(ITERATIONS / 2)), async (algorithm, measured) => {
    const elapsed = await time(() => issueCertificate({ actor: signer, algorithm }));
    if (measured) samples.certificateIssuance[algorithm].push(elapsed);
  });

  console.log("End-to-end signing...");
  await interleaved("signDocument", ITERATIONS, async (algorithm, measured) => {
    const state = setup[algorithm];
    const document = state.queue.shift();
    if (!document) throw new Error(`${algorithm}: ran out of prepared documents`);
    const elapsed = await time(() => signDocument({ actor: signer, documentId: document.id, certificateId: state.certificateId }));
    state.signed.push({ documentId: document.id, bytes: document.bytes });
    if (measured) samples.signDocument[algorithm].push(elapsed);
  });

  const targets = {} as Record<Algorithm, { documentId: string; bytes: Buffer; cms: Uint8Array; signatureId: string }>;
  const sizeRecords = {} as Record<Algorithm, { signatureBytes: number[]; cmsBytes: number[]; timestampBytes: number[] }>;
  for (const algorithm of ALGORITHMS) {
    const state = setup[algorithm];
    const records = await prisma.signature.findMany({
      where: { documentVersion: { documentId: { in: state.signed.map((item) => item.documentId) } } },
      select: { id: true, signatureBytes: true, cmsSignature: true, timestampToken: true, documentVersion: { select: { documentId: true } } },
    });
    if (records.length !== state.signed.length || records.some((record) => !record.cmsSignature || !record.timestampToken)) {
      throw new Error(`${algorithm}: expected every signature to carry a CMS export and a time-stamp`);
    }
    sizeRecords[algorithm] = {
      signatureBytes: records.map((record) => record.signatureBytes.length),
      cmsBytes: records.map((record) => record.cmsSignature!.length),
      timestampBytes: records.map((record) => record.timestampToken!.length),
    };
    const last = state.signed[state.signed.length - 1];
    const record = records.find((candidate) => candidate.documentVersion.documentId === last.documentId)!;
    targets[algorithm] = { documentId: last.documentId, bytes: last.bytes, cms: record.cmsSignature!, signatureId: record.id };
  }

  console.log("Verification and CMS verification...");
  await interleaved("verifyDocument", ITERATIONS, async (algorithm, measured) => {
    let outcome = "";
    const elapsed = await time(async () => {
      const result = await verifyDocument(verifier, targets[algorithm].documentId);
      outcome = result.outcome === "VALID" ? "" : `${result.outcome} (${result.reason})`;
    });
    if (outcome) throw new Error(`${algorithm}: verification returned ${outcome}`);
    if (measured) samples.verifyDocument[algorithm].push(elapsed);
  });
  await interleaved("cmsVerify", ITERATIONS, async (algorithm, measured) => {
    let status = "";
    const elapsed = await time(async () => {
      status = (await verifyDetachedSignature(targets[algorithm].cms, targets[algorithm].bytes)).status;
    });
    if (status !== "VALID") throw new Error(`${algorithm}: CMS verification returned ${status}`);
    if (measured) samples.cmsVerify[algorithm].push(elapsed);
  });

  console.log("Primitive operations: orchestrator against direct provider calls...");
  await interleaved("primitives", MICRO_ITERATIONS, async (algorithm, measured, round) => {
    const { keys, signature } = setup[algorithm];
    const provider = providerFor(algorithm);
    const pairs: [Operation, () => Promise<unknown>][][] = [
      [
        ["orchestratorSign", () => orchestrator.sign({ algorithm, message, privateKeyPem: keys.privateKeyPem })],
        ["providerSign", () => provider.sign(message, keys.privateKeyPem)],
      ],
      [
        ["orchestratorVerify", () => orchestrator.verify({ algorithm, message, signature, publicKeyPem: keys.publicKeyPem })],
        ["providerVerify", () => provider.verify(message, signature, keys.publicKeyPem)],
      ],
    ];
    for (const pair of pairs) {
      // Alternate which member of the pair runs first, so neither systematically benefits from the other's warm state.
      for (const [operation, run] of round % 2 === 0 ? pair : [...pair].reverse()) {
        const elapsed = await time(run);
        if (measured) samples[operation][algorithm].push(elapsed);
      }
    }
  });

  // --- Revocation list growth and anchoring commitment, untimed ---
  console.log("Revocation list growth and anchoring commitments...");
  const crlGrowth = {} as Record<Algorithm, number>;
  const commitmentBytes = {} as Record<Algorithm, number>;
  for (const algorithm of ALGORITHMS) {
    const before = await issueCrl({ actorUserId: admin.userId });
    const revocable = await issueCertificate({ actor: signer, algorithm });
    await revokeCertificate({ actor: admin, certificateId: revocable.id, reason: "superseded" });
    const after = await prisma.revocationList.findFirstOrThrow({ orderBy: { crlNumber: "desc" } });
    if (after.crlNumber <= before.crlNumber) throw new Error(`${algorithm}: revocation did not issue a new CRL`);
    crlGrowth[algorithm] = after.der.length - before.der.length;

    const commitment = await commitmentFor("SIGNATURE", targets[algorithm].signatureId);
    if (!commitment) throw new Error(`${algorithm}: no anchoring commitment for the signature`);
    commitmentBytes[algorithm] = commitment.length / 2;
  }

  const perAlgorithm = ALGORITHMS.map((algorithm) => {
    const metadata = orchestrator.describe(algorithm);
    return {
      algorithm,
      displayName: metadata.displayName,
      family: metadata.family,
      securityClass: metadata.securityClass,
      sizes: {
        publicKeySpkiBytes: setup[algorithm].publicKeySpkiBytes,
        certificateDerBytes: setup[algorithm].certificateDerBytes,
        signatureBytes: range(sizeRecords[algorithm].signatureBytes),
        cmsSignedDataBytes: range(sizeRecords[algorithm].cmsBytes),
        timestampTokenBytes: range(sizeRecords[algorithm].timestampBytes),
        anchoringCommitmentBytes: commitmentBytes[algorithm],
        crlGrowthPerRevokedCertificateBytes: crlGrowth[algorithm],
      },
      timings: Object.fromEntries(OPERATIONS.map((operation) => [operation, summarise(samples[operation][algorithm])])),
    };
  });

  const comparisons = Object.fromEntries(OPERATIONS.map((operation) => [operation, pairwiseComparisons(samples[operation])]));
  const agilityOverhead = ALGORITHMS.map((algorithm) => ({
    algorithm,
    sign: pairwiseComparisons({ orchestrator: samples.orchestratorSign[algorithm], provider: samples.providerSign[algorithm] })[0],
    verify: pairwiseComparisons({ orchestrator: samples.orchestratorVerify[algorithm], provider: samples.providerVerify[algorithm] })[0],
  }));

  fs.writeFileSync(
    resultFile,
    JSON.stringify({
      design: {
        interleaving: "Every timed operation runs in rounds; each round visits every algorithm once in an order shuffled by a seeded Mulberry32 generator; orchestrator/provider pairs alternate order by round.",
        seed: SEED,
        measuredRounds: rounds,
      },
      algorithms: perAlgorithm,
      comparisons,
      agilityOverhead,
      samples: Object.fromEntries(OPERATIONS.map((operation) => [operation, Object.fromEntries(ALGORITHMS.map((algorithm) => [algorithm, round4(samples[operation][algorithm])]))])),
    }),
  );
  await prisma.$disconnect();
}

// ---------------------------------------------------------------------------------------------
// Parent: isolated installation, worker, report
// ---------------------------------------------------------------------------------------------

async function parent() {
  const output = path.resolve(stringArg("--output") ?? path.join(ROOT, "public", "migration-study.json"));
  const runId = `${Date.now()}-${randomBytes(4).toString("hex")}`;
  const runDirectory = path.join(STUDY_ROOT, runId);
  const env: Record<string, string> = {
    DATABASE_URL: sqliteUrl(path.join(runDirectory, "study.db")),
    STORAGE_ROOT: path.join(runDirectory, "storage"),
    MASTER_KEY_PATH: path.join(runDirectory, "keys", "master.key"),
    SECURITY_LAB_ROOT: path.join(runDirectory, "lab"),
    JWT_SECRET: randomBytes(32).toString("hex"),
  };
  const childEnv = { ...process.env, ...env };
  const developmentDatabase = path.join(ROOT, "prisma", "dev.db");
  const fingerprint = (file: string) => (fs.existsSync(file) ? sha256Hex(fs.readFileSync(file)) : null);
  const developmentBefore = fingerprint(developmentDatabase);
  const startedAt = new Date();

  console.log(`Migration study: n=${ITERATIONS} end-to-end, n=${MICRO_ITERATIONS} primitive operations, ${WARMUP} warm-up rounds, seed ${SEED}.\n`);
  try {
    fs.mkdirSync(path.join(env.STORAGE_ROOT, "documents"), { recursive: true });
    fs.mkdirSync(path.dirname(env.MASTER_KEY_PATH), { recursive: true });
    fs.writeFileSync(env.MASTER_KEY_PATH, randomBytes(32).toString("base64"));
    execFileSync(NODE, [path.join(ROOT, "node_modules", "prisma", "build", "index.js"), "migrate", "deploy"], { env: childEnv, stdio: "pipe" });

    const resultFile = path.join(runDirectory, "result.json");
    const passthrough = process.argv.slice(2).filter((argument, index, all) => argument !== "--output" && all[index - 1] !== "--output");
    const run = spawnSync(NODE, [path.join(ROOT, "node_modules", "tsx", "dist", "cli.mjs"), path.join("scripts", "migration-study.ts"), WORKER_FLAG, resultFile, ...passthrough], {
      env: childEnv,
      stdio: "inherit",
      cwd: ROOT,
    });
    if (run.status !== 0) throw new Error(`the study worker exited with ${run.status}`);

    const result = JSON.parse(fs.readFileSync(resultFile, "utf8"));
    const developmentAfter = fingerprint(developmentDatabase);
    const finishedAt = new Date();
    const report = {
      schemaVersion: MIGRATION_STUDY_SCHEMA_VERSION,
      generatedAt: finishedAt.toISOString(),
      startedAt: startedAt.toISOString(),
      durationMs: finishedAt.getTime() - startedAt.getTime(),
      environment: environment(),
      parameters: { iterations: ITERATIONS, microIterations: MICRO_ITERATIONS, warmupRounds: WARMUP, seed: SEED, timer: "process.hrtime.bigint()" },
      isolation: {
        installation: "throwaway SQLite database, storage, master key and JWT secret, deleted after the run",
        developmentDatabaseUnchanged: developmentBefore === developmentAfter,
      },
      methodology: [
        "Every size and timing comes from an operation performed in this run, through the application's own services.",
        "Timed operations run in interleaved rounds: each round visits every algorithm once in a seeded random order, so drift, warm-up and database growth are spread across algorithms instead of being attributed to whichever ran at a given time.",
        "End-to-end signing includes hashing, the signature, two RFC 3161 time-stamps (over the signature value and inside CMS), CMS assembly, encrypted storage and audit logging; documents are uploaded before timing starts.",
        "Verification runs the ten-step workflow against the same signed document each time; every run must return VALID or the study aborts. CMS verification is the standalone RFC 5652 check of that document's export.",
        "Orchestrator and direct-provider timings sign and verify the same 32-byte digest with the same key, alternating which runs first, isolating the cost of the crypto-agility layer.",
        "Pairwise comparisons use the two-sided Mann-Whitney U test (primary) and Welch's t-test, Holm-adjusted across the pairs of each operation; effect sizes are Cliff's delta and the Hodges-Lehmann shift.",
        "CRL growth is the DER length difference between a list issued just before and the list issued by revoking one certificate of the algorithm.",
      ],
      notes: [
        "Absolute timings depend on this machine and on SQLite and filesystem latency; compare algorithms within one run.",
        "Measurements run sequentially in one process; garbage collection is not forced.",
        "The time-stamp authority and the CA sign with a fixed classical algorithm in every run, so time-stamp token and CRL sizes are expected not to depend on the end-entity algorithm; the study measures that rather than assuming it.",
        "One machine only: cross-machine reproducibility is not established by a single run.",
      ],
      ...result,
    };
    fs.mkdirSync(path.dirname(output), { recursive: true });
    fs.writeFileSync(output, `${JSON.stringify(report, null, 2)}\n`);

    console.log(`\nWrote ${path.relative(ROOT, output)} in ${(report.durationMs / 1000).toFixed(1)} s; development database unchanged: ${report.isolation.developmentDatabaseUnchanged}`);
    const width = Math.max(...report.algorithms.map((row: { displayName: string }) => row.displayName.length)) + 2;
    console.log(`${"Algorithm".padEnd(width)}${"cert".padEnd(7)}${"sig".padEnd(7)}${"CMS".padEnd(7)}${"sign e2e".padEnd(12)}${"verify e2e".padEnd(13)}cms verify`);
    for (const row of report.algorithms) {
      console.log(
        row.displayName.padEnd(width) +
          String(row.sizes.certificateDerBytes).padEnd(7) +
          String(row.sizes.signatureBytes.median).padEnd(7) +
          String(row.sizes.cmsSignedDataBytes.median).padEnd(7) +
          `${row.timings.signDocument.medianMs.toFixed(2)} ms`.padEnd(12) +
          `${row.timings.verifyDocument.medianMs.toFixed(2)} ms`.padEnd(13) +
          `${row.timings.cmsVerify.medianMs.toFixed(2)} ms`,
      );
    }
  } finally {
    fs.rmSync(runDirectory, { recursive: true, force: true, maxRetries: 10, retryDelay: 300 });
  }
}

const workerIndex = process.argv.indexOf(WORKER_FLAG);
if (process.argv[1]?.endsWith("migration-study.ts")) {
  const main = workerIndex === -1 ? parent() : worker(process.argv[workerIndex + 1]);
  main.catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}
