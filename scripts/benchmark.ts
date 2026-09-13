// Measures sign/verify/hash/key-generation cost per algorithm and writes the results, with their
// statistics and the environment they were measured in, to public/benchmarks.json, which the
// /benchmarks and /algorithms pages render.
//
//   npm run benchmark [-- --iterations 200 --keygen-iterations 20 --warmup 20]
//   npm run benchmark -- --smoke          quick run for CI, written to storage/benchmarks-smoke.json
//   npm run benchmark -- --output <file>  write somewhere else
//
// Every number comes from an operation actually performed on this machine. The output file is
// gitignored on purpose: a clone ships with no benchmark data rather than with someone else's
// numbers presented as its own. Statistics definitions are in lib/benchmarks/statistics.ts.
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { summarise, type SampleSummary } from "../lib/benchmarks/statistics";
import { sha256 } from "../lib/crypto/hash";
import { ALGORITHMS, orchestrator, type Algorithm, type KeyPairPem } from "../lib/crypto/orchestrator";
import { prisma } from "../lib/db";

export const BENCHMARK_SCHEMA_VERSION = 2;

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

const SMOKE = process.argv.includes("--smoke");
const ITERATIONS = numericArg("--iterations", SMOKE ? 10 : 200);
const KEYGEN_ITERATIONS = numericArg("--keygen-iterations", SMOKE ? 2 : 20);
const WARMUP = numericArg("--warmup", SMOKE ? 2 : 20);
const OUTPUT = path.resolve(
  stringArg("--output") ??
    (SMOKE ? path.join(process.cwd(), "storage", "benchmarks-smoke.json") : path.join(process.cwd(), "public", "benchmarks.json")),
);

const PAYLOADS = [
  { label: "1 KB", bytes: 1024 },
  { label: "1 MB", bytes: 1024 * 1024 },
];

async function measure(iterations: number, operation: () => unknown): Promise<SampleSummary> {
  // Untimed warm-up first, so JIT compilation and cache filling are not attributed to the algorithm.
  for (let index = 0; index < Math.min(WARMUP, iterations); index += 1) await operation();

  const samplesMs: number[] = [];
  for (let index = 0; index < iterations; index += 1) {
    const start = process.hrtime.bigint();
    await operation();
    samplesMs.push(Number(process.hrtime.bigint() - start) / 1_000_000);
  }
  return summarise(samplesMs);
}

async function certificateSizes(): Promise<Partial<Record<Algorithm, number>>> {
  const sizes: Partial<Record<Algorithm, number>> = {};
  try {
    for (const algorithm of ALGORITHMS) {
      const certificate = await prisma.certificate.findFirst({ where: { algorithm }, orderBy: { issuedAt: "desc" } });
      if (!certificate) continue;
      sizes[algorithm] = Buffer.from(
        certificate.certPem.split(/\r?\n/).filter((line) => !line.startsWith("-----")).join(""),
        "base64",
      ).length;
    }
  } catch {
    // No database yet: sizes stay null and the page says so.
  }
  return sizes;
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
    cpuSpeedMHz: cpus[0]?.speed ?? null,
    cores: cpus.length,
    memoryGB: Math.round(os.totalmem() / 1024 ** 3),
    freeMemoryGBAtStart: Math.round((os.freemem() / 1024 ** 3) * 10) / 10,
    loadAverage: os.platform() === "win32" ? null : os.loadavg(),
    gitCommit: git(["rev-parse", "--short", "HEAD"]),
    gitTreeDirty: status === null ? null : status.length > 0,
  };
}

async function main() {
  const startedAt = new Date();
  console.log(
    `${SMOKE ? "SMOKE " : ""}Benchmark: ${ALGORITHMS.length} algorithms, n=${ITERATIONS} per sign/verify/hash measurement, ` +
      `n=${KEYGEN_ITERATIONS} key generations, ${WARMUP} warm-up iterations.\n`,
  );

  const payloads = PAYLOADS.map((payload) => ({ ...payload, data: Buffer.alloc(payload.bytes, 0x5a) }));
  const certificates = await certificateSizes();
  const results = [];

  for (const algorithm of ALGORITHMS) {
    const metadata = orchestrator.describe(algorithm);
    process.stdout.write(`${metadata.displayName}: keys...`);

    const keyGeneration = await measure(KEYGEN_ITERATIONS, () => orchestrator.generateKeyPair(algorithm));
    const keys: KeyPairPem = await orchestrator.generateKeyPair(algorithm);

    const perPayload = [];
    for (const payload of payloads) {
      process.stdout.write(` ${payload.label}...`);
      const hash = await measure(ITERATIONS, () => sha256(payload.data));
      const message = sha256(payload.data);
      const sign = await measure(ITERATIONS, () => orchestrator.sign({ algorithm, message, privateKeyPem: keys.privateKeyPem }));
      const signature = await orchestrator.sign({ algorithm, message, privateKeyPem: keys.privateKeyPem });
      const verify = await measure(ITERATIONS, () =>
        orchestrator.verify({ algorithm, message, signature, publicKeyPem: keys.publicKeyPem }),
      );

      // Guards against timing an operation that silently does nothing useful.
      if (!(await orchestrator.verify({ algorithm, message, signature, publicKeyPem: keys.publicKeyPem }))) {
        throw new Error(`${algorithm}: benchmark signature failed to verify`);
      }

      perPayload.push({ label: payload.label, payloadBytes: payload.bytes, hash, sign, verify, signatureBytes: signature.length });
    }

    const signature = await orchestrator.sign({ algorithm, message: sha256(payloads[0].data), privateKeyPem: keys.privateKeyPem });
    results.push({
      algorithm,
      displayName: metadata.displayName,
      description: metadata.description,
      family: metadata.family,
      securityClass: metadata.securityClass,
      implementation: metadata.implementation.version,
      signatureBytes: signature.length,
      declaredSignatureBytes: metadata.signature.fixedBytes,
      publicKeyPemBytes: Buffer.byteLength(keys.publicKeyPem),
      privateKeyPemBytes: Buffer.byteLength(keys.privateKeyPem),
      certificateDerBytes: certificates[algorithm] ?? null,
      keyGeneration,
      payloads: perPayload,
    });
    console.log(" done");
  }

  const finishedAt = new Date();
  const output = {
    schemaVersion: BENCHMARK_SCHEMA_VERSION,
    smoke: SMOKE,
    generatedAt: finishedAt.toISOString(),
    startedAt: startedAt.toISOString(),
    durationMs: finishedAt.getTime() - startedAt.getTime(),
    environment: environment(),
    parameters: {
      iterations: ITERATIONS,
      keyGenerationIterations: KEYGEN_ITERATIONS,
      warmupIterations: WARMUP,
      payloadSizes: PAYLOADS.map((payload) => payload.bytes),
      timer: "process.hrtime.bigint()",
    },
    methodology: [
      "Each sample is the wall-clock duration of one operation, timed with process.hrtime.bigint() after untimed warm-up iterations.",
      "Measurements run sequentially in one process, algorithm by algorithm; garbage collection is not forced, so its pauses fall inside some samples and show up as outliers.",
      "Standard deviation is the sample standard deviation (n - 1). The 95% confidence interval is for the mean, using Student's t with a conservative table lookup.",
      "Percentiles use linear interpolation (Hyndman & Fan type 7). Outliers are counted with Tukey's fences and are not removed.",
      "Timing samples have long right tails and are not strictly independent, so compare medians first and treat the confidence interval as indicative.",
    ],
    notes: [
      "Absolute timings depend on this machine; the comparison between algorithms is the point.",
      "IMPORTANT: the timings compare implementations as much as algorithms. RSA-PSS, ECDSA and ML-DSA run in OpenSSL's native code through node:crypto, while Ed25519 runs in pure JavaScript through @noble/ed25519, which CLAUDE.md Section 1 mandates. The Ed25519 timings should be read as 'this library on this runtime', not as a property of EdDSA.",
      "Sign and verify operate on the 32-byte SHA-256 digest, so their cost does not vary with document size. The hash column is where document size shows up.",
      "The size columns (signature, key, certificate) are properties of the algorithms and encodings, not of the implementation.",
      "Certificate sizes are DER lengths of certificates actually issued by this installation's CA, read from the database; null if none have been issued.",
      ...(SMOKE ? ["SMOKE RUN: sample sizes are too small for comparison; this output only proves the benchmark runs."] : []),
    ],
    algorithms: results,
  };

  fs.mkdirSync(path.dirname(OUTPUT), { recursive: true });
  fs.writeFileSync(OUTPUT, `${JSON.stringify(output, null, 2)}\n`);

  console.log(`\nWrote ${path.relative(process.cwd(), OUTPUT)} in ${(output.durationMs / 1000).toFixed(1)} s`);
  console.log(`Environment: ${output.environment.cpu}, Node ${output.environment.node}, OpenSSL ${output.environment.openssl}\n`);

  const pad = (value: string, width: number) => value.padEnd(width);
  console.log(`${pad("Algorithm", 18)}${pad("sign median", 14)}${pad("sign 95% CI (mean)", 24)}${pad("verify median", 15)}sig bytes`);
  for (const result of results) {
    const first = result.payloads[0];
    const ci = first.sign.ci95Ms ? `${first.sign.ci95Ms[0].toFixed(3)}-${first.sign.ci95Ms[1].toFixed(3)} ms` : "n/a";
    console.log(
      pad(result.displayName, 18) +
        pad(`${first.sign.medianMs.toFixed(3)} ms`, 14) +
        pad(ci, 24) +
        pad(`${first.verify.medianMs.toFixed(3)} ms`, 15) +
        result.signatureBytes,
    );
  }
}

main()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(() => prisma.$disconnect());
