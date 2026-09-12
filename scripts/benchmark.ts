// Measures sign/verify/hash/key-generation cost per algorithm and writes the results
// to public/benchmarks.json, which the /benchmarks page renders.
//
//   npm run benchmark [-- --iterations 200]
//
// Every number here comes from an operation actually performed on this machine. The
// file is gitignored on purpose: a clone ships with no benchmark data rather than with
// someone else's numbers presented as yours.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { sha256 } from "../lib/crypto/hash";
import { orchestrator } from "../lib/crypto/orchestrator";
import { ALGORITHMS, type Algorithm, type KeyPairPem } from "../lib/crypto/types";
import { prisma } from "../lib/db";

const OUTPUT = path.join(process.cwd(), "public", "benchmarks.json");

function numericArg(flag: string, fallback: number): number {
  const index = process.argv.indexOf(flag);
  if (index === -1) return fallback;
  const value = Number(process.argv[index + 1]);
  return Number.isFinite(value) && value > 0 ? Math.floor(value) : fallback;
}

const ITERATIONS = numericArg("--iterations", 200);
const KEYGEN_ITERATIONS = numericArg("--keygen-iterations", 5);

const PAYLOADS = [
  { label: "1 KB", bytes: 1024 },
  { label: "1 MB", bytes: 1024 * 1024 },
];

type Stats = {
  iterations: number;
  meanMs: number;
  medianMs: number;
  p95Ms: number;
  minMs: number;
  maxMs: number;
};

function summarise(samplesNs: bigint[]): Stats {
  const ms = samplesNs.map((value) => Number(value) / 1_000_000).sort((a, b) => a - b);
  const total = ms.reduce((sum, value) => sum + value, 0);
  const at = (fraction: number) => ms[Math.min(ms.length - 1, Math.floor(ms.length * fraction))];

  return {
    iterations: ms.length,
    meanMs: total / ms.length,
    medianMs: at(0.5),
    p95Ms: at(0.95),
    minMs: ms[0],
    maxMs: ms[ms.length - 1],
  };
}

async function measure(iterations: number, operation: () => Promise<unknown>): Promise<Stats> {
  // A few untimed iterations first, so JIT warm-up is not attributed to the algorithm.
  for (let index = 0; index < Math.min(5, iterations); index += 1) await operation();

  const samples: bigint[] = [];
  for (let index = 0; index < iterations; index += 1) {
    const start = process.hrtime.bigint();
    await operation();
    samples.push(process.hrtime.bigint() - start);
  }
  return summarise(samples);
}

async function certificateSizes(): Promise<Partial<Record<Algorithm, number>>> {
  const sizes: Partial<Record<Algorithm, number>> = {};
  try {
    for (const algorithm of ALGORITHMS) {
      const certificate = await prisma.certificate.findFirst({
        where: { algorithm },
        orderBy: { issuedAt: "desc" },
      });
      if (!certificate) continue;
      const der = Buffer.from(
        certificate.certPem
          .split(/\r?\n/)
          .filter((line) => !line.startsWith("-----"))
          .join(""),
        "base64",
      );
      sizes[algorithm] = der.length;
    }
  } catch {
    // No database yet: sizes stay undefined and the page says so.
  }
  return sizes;
}

async function main() {
  console.log(
    `Benchmarking ${ALGORITHMS.length} algorithms: ${ITERATIONS} sign+verify cycles per payload size, ` +
      `${KEYGEN_ITERATIONS} key generations each.\n`,
  );

  const payloads = PAYLOADS.map((payload) => ({
    ...payload,
    data: Buffer.alloc(payload.bytes, 0x5a),
  }));

  const certificates = await certificateSizes();
  const results = [];

  for (const algorithm of ALGORITHMS) {
    const description = orchestrator.describe(algorithm);
    process.stdout.write(`${description.displayName}: keys...`);

    const keyGeneration = await measure(KEYGEN_ITERATIONS, () =>
      orchestrator.generateKeyPair(algorithm),
    );
    const keys: KeyPairPem = await orchestrator.generateKeyPair(algorithm);

    const perPayload = [];
    for (const payload of payloads) {
      process.stdout.write(` ${payload.label}...`);

      const hash = await measure(ITERATIONS, async () => sha256(payload.data));
      const digest = sha256(payload.data);

      const sign = await measure(ITERATIONS, () =>
        orchestrator.sign({ algorithm, digest, privateKeyPem: keys.privateKeyPem }),
      );

      const signature = await orchestrator.sign({
        algorithm,
        digest,
        privateKeyPem: keys.privateKeyPem,
      });

      const verify = await measure(ITERATIONS, () =>
        orchestrator.verify({
          algorithm,
          digest,
          signature,
          publicKeyPem: keys.publicKeyPem,
        }),
      );

      // Guards against timing an operation that silently does nothing useful.
      const verified = await orchestrator.verify({
        algorithm,
        digest,
        signature,
        publicKeyPem: keys.publicKeyPem,
      });
      if (!verified) throw new Error(`${algorithm}: benchmark signature failed to verify`);

      perPayload.push({
        label: payload.label,
        payloadBytes: payload.bytes,
        hash,
        sign,
        verify,
        signatureBytes: signature.length,
      });
    }

    const digest = sha256(payloads[0].data);
    const signature = await orchestrator.sign({
      algorithm,
      digest,
      privateKeyPem: keys.privateKeyPem,
    });

    results.push({
      algorithm,
      displayName: description.displayName,
      description: description.description,
      signatureBytes: signature.length,
      declaredSignatureBytes: description.signatureByteLength,
      publicKeyPemBytes: Buffer.byteLength(keys.publicKeyPem),
      privateKeyPemBytes: Buffer.byteLength(keys.privateKeyPem),
      certificateDerBytes: certificates[algorithm] ?? null,
      keyGeneration,
      payloads: perPayload,
    });

    console.log(" done");
  }

  const cpus = os.cpus();
  const output = {
    generatedAt: new Date().toISOString(),
    environment: {
      node: process.version,
      platform: `${os.platform()} ${os.release()}`,
      arch: os.arch(),
      cpu: cpus[0]?.model?.trim() ?? "unknown",
      cores: cpus.length,
      memoryGB: Math.round(os.totalmem() / 1024 ** 3),
    },
    parameters: {
      iterations: ITERATIONS,
      keyGenerationIterations: KEYGEN_ITERATIONS,
      payloadSizes: PAYLOADS.map((payload) => payload.bytes),
      warmupIterations: 5,
      timer: "process.hrtime.bigint()",
    },
    notes: [
      "Absolute timings depend on this machine; the comparison between algorithms is the point.",
      "IMPORTANT: the timings compare implementations as much as algorithms. RSA-PSS and ECDSA run in OpenSSL's native code through node:crypto, while Ed25519 runs in pure JavaScript through @noble/ed25519, which CLAUDE.md Section 1 mandates. A native Ed25519 implementation is normally faster than both of the others, so the Ed25519 timings here should be read as 'this library on this runtime', not as a property of EdDSA.",
      "Sign and verify operate on the 32-byte SHA-256 digest, so their cost does not vary with document size. The hash column is where document size shows up.",
      "The size columns (signature, key, certificate) are properties of the algorithms themselves and are not affected by the implementation difference above.",
      "RSA-PSS and ECDSA are randomised, Ed25519 is deterministic; this affects repeatability of the output, not the timings.",
      "Certificate sizes are DER byte lengths of certificates actually issued by this installation's CA, read from the database. They are null if none have been issued yet.",
    ],
    algorithms: results,
  };

  fs.mkdirSync(path.dirname(OUTPUT), { recursive: true });
  fs.writeFileSync(OUTPUT, `${JSON.stringify(output, null, 2)}\n`);

  console.log(`\nWrote ${path.relative(process.cwd(), OUTPUT)}`);
  console.log(`Environment: ${output.environment.cpu}, Node ${output.environment.node}\n`);

  const pad = (value: string, width: number) => value.padEnd(width);
  console.log(
    `${pad("Algorithm", 18)}${pad("sign median", 14)}${pad("verify median", 15)}${pad("sig bytes", 11)}cert bytes`,
  );
  for (const result of results) {
    const first = result.payloads[0];
    console.log(
      pad(result.displayName, 18) +
        pad(`${first.sign.medianMs.toFixed(3)} ms`, 14) +
        pad(`${first.verify.medianMs.toFixed(3)} ms`, 15) +
        pad(String(result.signatureBytes), 11) +
        (result.certificateDerBytes ?? "-"),
    );
  }
}

main()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(() => prisma.$disconnect());
