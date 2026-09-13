// End-to-end regression against a completely separate installation.
//
//   npm run build && npm run e2e
//
// Creates a throwaway installation under storage/e2e/<run id> (its own SQLite database, document
// storage, master key, JWT secret and Security Lab root), migrates and seeds it, starts its own
// local chain and the production build (`next start`) on ports that do not collide with the
// development server, `npm run chain` or the test chain, then drives the demo over real HTTP.
// The development database is fingerprinted before and after to show it was not touched. The
// run directory is deleted afterwards; storage/e2e/report.json keeps the results.
import { execFileSync, spawn, spawnSync, type ChildProcess } from "node:child_process";
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { PrismaClient } from "@prisma/client";
import { sha256Hex } from "../lib/crypto/hash";
import { ALGORITHMS, orchestrator } from "../lib/crypto/orchestrator";

const ROOT = process.cwd();
const NODE = process.execPath;
export const E2E_PORT = 3100;
export const E2E_CHAIN_PORT = 8547;
export const E2E_ROOT = path.join(ROOT, "storage", "e2e");
const BASE = `http://127.0.0.1:${E2E_PORT}`;
const PASSWORD = "demo1234";

const sqliteUrl = (file: string) => `file:${file.split(path.sep).join("/")}`;

/** The complete environment the isolated installation runs with. Nothing points outside runDirectory. */
export function e2eEnvironment(runDirectory: string): Record<string, string> {
  return {
    DATABASE_URL: sqliteUrl(path.join(runDirectory, "e2e.db")),
    STORAGE_ROOT: path.join(runDirectory, "storage"),
    MASTER_KEY_PATH: path.join(runDirectory, "keys", "master.key"),
    SECURITY_LAB_ROOT: path.join(runDirectory, "lab"),
    ANCHOR_RPC_URL: `http://127.0.0.1:${E2E_CHAIN_PORT}`,
    JWT_SECRET: randomBytes(32).toString("hex"),
    NODE_ENV: "production",
    PORT: String(E2E_PORT),
  };
}

type Result = { name: string; status: "PASS" | "FAIL" | "SKIPPED"; detail: string };
const results: Result[] = [];

class CheckFailure extends Error {}
function check(condition: unknown, message: string): asserts condition {
  if (!condition) throw new CheckFailure(message);
}

async function step(name: string, run: () => Promise<string | void>) {
  process.stdout.write(`- ${name} ... `);
  try {
    const detail = (await run()) ?? "";
    results.push({ name, status: "PASS", detail });
    console.log(`PASS${detail ? ` (${detail})` : ""}`);
  } catch (error) {
    const detail = error instanceof Error ? error.message.split(/\r?\n/, 1)[0] : String(error);
    results.push({ name, status: "FAIL", detail });
    console.log(`FAIL: ${detail}`);
  }
}

function skip(name: string, detail: string) {
  results.push({ name, status: "SKIPPED", detail });
  console.log(`- ${name} ... SKIPPED (${detail})`);
}

function fingerprint(file: string): string | null {
  // Hashing goes through the crypto layer, like everywhere else outside lib/crypto.
  return fs.existsSync(file) ? sha256Hex(fs.readFileSync(file)) : null;
}

async function waitFor(url: string, child: ChildProcess, label: string, timeoutMs = 180_000, init?: RequestInit) {
  const started = Date.now();
  for (;;) {
    if (child.exitCode !== null) throw new Error(`${label} exited with ${child.exitCode}`);
    try {
      const response = await fetch(url, init);
      if (response.status < 500) return;
    } catch {
      // not listening yet
    }
    if (Date.now() - started > timeoutMs) throw new Error(`${label} did not become ready within ${timeoutMs / 1000} s`);
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
}

async function stop(child: ChildProcess | null) {
  if (!child || child.exitCode !== null) return;
  child.kill();
  const started = Date.now();
  while (child.exitCode === null && child.signalCode === null && Date.now() - started < 10_000) {
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
}

/** Every response body is checked: no API may return key material or password hashes. */
function assertClean(text: string, what: string) {
  check(!/PRIVATE KEY|encryptedPrivateKey|passwordHash|\$2[aby]\$\d\d\$/.test(text), `${what} contained key material or a password hash`);
}

async function api(cookie: string | null, method: string, url: string, body?: unknown, origin = BASE) {
  const headers: Record<string, string> = { Origin: origin };
  if (cookie) headers.Cookie = cookie;
  let payload: BodyInit | undefined;
  if (body instanceof FormData) payload = body;
  else if (body !== undefined) {
    payload = JSON.stringify(body);
    headers["Content-Type"] = "application/json";
  }
  const response = await fetch(`${BASE}${url}`, { method, headers, body: payload, redirect: "manual" });
  const text = await response.text();
  assertClean(text, `${method} ${url}`);
  let json: any = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }
  return { status: response.status, json, headers: response.headers, text };
}

async function login(email: string, password = PASSWORD) {
  const response = await fetch(`${BASE}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: BASE },
    body: JSON.stringify({ email, password }),
  });
  return { status: response.status, cookie: response.headers.get("set-cookie")?.split(";")[0] ?? null };
}

async function main() {
  if (!fs.existsSync(path.join(ROOT, ".next", "BUILD_ID"))) {
    throw new Error("No production build found. Run `npm run build` first.");
  }

  const runId = `${Date.now()}-${randomBytes(3).toString("hex")}`;
  const runDirectory = path.join(E2E_ROOT, runId);
  const env = e2eEnvironment(runDirectory);
  const childEnv = { ...process.env, ...env };
  const devDatabase = path.join(ROOT, "prisma", "dev.db");
  const devBefore = fingerprint(devDatabase);
  const openssl = spawnSync("openssl", ["version"], { encoding: "utf8" }).status === 0;
  const started = Date.now();

  fs.mkdirSync(path.join(env.STORAGE_ROOT, "documents"), { recursive: true });
  fs.mkdirSync(path.dirname(env.MASTER_KEY_PATH), { recursive: true });
  fs.writeFileSync(env.MASTER_KEY_PATH, randomBytes(32).toString("base64"));

  let chain: ChildProcess | null = null;
  let server: ChildProcess | null = null;
  let serverLog = "";
  const database = new PrismaClient({ datasourceUrl: env.DATABASE_URL });

  try {
    console.log(`E2E run ${runId}\nIsolated installation: ${path.relative(ROOT, runDirectory)}\n`);

    await step("migrate a fresh database", async () => {
      execFileSync(NODE, [path.join(ROOT, "node_modules", "prisma", "build", "index.js"), "migrate", "deploy"], { env: childEnv, stdio: "pipe" });
    });
    await step("seed demo data through the real services", async () => {
      const output = execFileSync(NODE, [path.join(ROOT, "node_modules", "tsx", "dist", "cli.mjs"), "prisma/seed.ts"], { env: childEnv, encoding: "utf8", stdio: "pipe" });
      check(/chain intact/.test(output), "seed did not report an intact audit chain");
      return output.match(/Audit log\s+: .+/)?.[0];
    });

    chain = spawn(NODE, [path.join(ROOT, "node_modules", "hardhat", "internal", "cli", "bootstrap.js"), "node", "--hostname", "127.0.0.1", "--port", String(E2E_CHAIN_PORT)], {
      cwd: ROOT,
      stdio: ["ignore", "ignore", "ignore"], // Hardhat prints its development account keys on stdout.
    });
    server = spawn(NODE, [path.join(ROOT, "node_modules", "next", "dist", "bin", "next"), "start", "-p", String(E2E_PORT), "-H", "127.0.0.1"], {
      cwd: ROOT,
      env: childEnv,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const keepLog = (chunk: Buffer) => {
      serverLog = (serverLog + chunk.toString()).slice(-4000);
    };
    server.stdout?.on("data", keepLog);
    server.stderr?.on("data", keepLog);

    await step("start the local chain and the production server", async () => {
      await waitFor(`http://127.0.0.1:${E2E_CHAIN_PORT}`, chain!, "chain", 120_000, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_chainId", params: [] }),
      });
      await waitFor(`${BASE}/login`, server!, "next start");
    });

    await step("public pages render and protected pages redirect when signed out", async () => {
      const loginPage = await fetch(`${BASE}/login`);
      check(loginPage.status === 200, `/login returned ${loginPage.status}`);
      for (const header of ["content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy"]) {
        check(loginPage.headers.get(header), `missing ${header} header`);
      }
      check(!loginPage.headers.get("x-powered-by"), "x-powered-by header is present");
      const dashboard = await fetch(`${BASE}/dashboard`, { redirect: "manual" });
      check([302, 303, 307, 308].includes(dashboard.status) && /\/login/.test(dashboard.headers.get("location") ?? ""), `/dashboard signed out returned ${dashboard.status}`);
    });

    const cookies: Record<string, string> = {};
    await step("all four demo roles sign in", async () => {
      for (const email of ["admin@demo", "signer@demo", "verifier@demo", "viewer@demo"]) {
        const result = await login(email);
        check(result.status === 200 && result.cookie, `${email} login returned ${result.status}`);
        cookies[email] = result.cookie;
      }
    });
    const [admin, signer, verifier, viewer] = ["admin@demo", "signer@demo", "verifier@demo", "viewer@demo"].map((email) => cookies[email] ?? null);

    await step("every application page renders for an admin", async () => {
      const pages: [string, string][] = [
        ["/dashboard", "Dashboard"],
        ["/documents", "Documents"],
        ["/certificates", "Certificates"],
        ["/algorithms", "Algorithms"],
        ["/audit", "Audit log"],
        ["/anchoring", "Blockchain anchoring"],
        ["/security-lab", "Security Lab"],
        ["/benchmarks", "Benchmarks"],
      ];
      for (const [page, heading] of pages) {
        const response = await fetch(`${BASE}${page}`, { headers: { Cookie: admin! } });
        const html = await response.text();
        check(response.status === 200 && html.includes(heading), `${page} returned ${response.status} without "${heading}"`);
        check(!html.includes("PRIVATE KEY"), `${page} contains key material`);
      }
      return `${pages.length} pages`;
    });

    await step("seeded documents verify as the demo expects", async () => {
      const { json } = await api(viewer, "GET", "/api/documents");
      const documents = json.documents as { id: string; filename: string; status: string }[];
      const unsigned = documents.find((document) => document.filename === "draft-policy.md");
      const tampered = documents.find((document) => document.filename === "invoice-tampered.txt");
      const signed = documents.filter((document) => document !== unsigned && document !== tampered);
      check(unsigned && tampered, "seeded unsigned or tampered document missing");
      check(signed.length === ALGORITHMS.length, `expected ${ALGORITHMS.length} signed samples, found ${signed.length}`);

      for (const document of signed) {
        const { status, json: body } = await api(verifier, "POST", `/api/documents/${document.id}/verify`);
        check(status === 200 && body.result.outcome === "VALID" && body.result.trust.trustedTime, `${document.filename}: ${status} ${body?.result?.outcome}/${body?.result?.reason}`);
      }
      const tamperedResult = await api(verifier, "POST", `/api/documents/${tampered!.id}/verify`);
      check(tamperedResult.json.result.outcome === "INVALID" && tamperedResult.json.result.reason === "HASH_MISMATCH", `tampered: ${tamperedResult.json.result.outcome}/${tamperedResult.json.result.reason}`);
      const unsignedResult = await api(verifier, "POST", `/api/documents/${unsigned!.id}/verify`);
      check(unsignedResult.status === 409 && unsignedResult.json.notSigned === true, `unsigned: ${unsignedResult.status}`);
      return `${signed.length} VALID, tampered INVALID/HASH_MISMATCH, unsigned 409`;
    });

    const created: Record<string, { documentId: string; certificateId: string; content: Buffer }> = {};
    await step("issue, upload, sign and verify under every registered algorithm", async () => {
      for (const algorithm of ALGORITHMS) {
        const issued = await api(signer, "POST", "/api/certificates", { algorithm });
        check(issued.status === 201, `${algorithm} issue: ${issued.status}`);
        const content = Buffer.from(`E2E document signed under ${algorithm} at ${new Date().toISOString()}`);
        const form = new FormData();
        form.append("file", new Blob([new Uint8Array(content)], { type: "text/plain" }), `e2e-${algorithm}.txt`);
        const uploaded = await api(signer, "POST", "/api/documents", form);
        check(uploaded.status === 201, `${algorithm} upload: ${uploaded.status}`);
        const signed = await api(signer, "POST", `/api/documents/${uploaded.json.document.id}/sign`, { certificateId: issued.json.certificate.id });
        check(signed.status === 201, `${algorithm} sign: ${signed.status} ${signed.json?.error ?? ""}`);
        const verified = await api(verifier, "POST", `/api/documents/${uploaded.json.document.id}/verify`);
        check(verified.json?.result?.outcome === "VALID", `${algorithm} verify: ${verified.json?.result?.outcome}/${verified.json?.result?.reason}`);
        created[algorithm] = { documentId: uploaded.json.document.id, certificateId: issued.json.certificate.id, content };
      }
      return `${ALGORITHMS.length} algorithms`;
    });

    const opensslAlgorithms = ALGORITHMS.filter((algorithm) => orchestrator.describe(algorithm).interoperability.opensslCms && created[algorithm]);
    if (!openssl) {
      skip("exported CMS signatures verify with the OpenSSL CLI", "no openssl binary on PATH");
    } else {
      await step("exported CMS signatures verify with the OpenSSL CLI", async () => {
        const work = path.join(runDirectory, "openssl");
        fs.mkdirSync(work, { recursive: true });
        const ca = await fetch(`${BASE}/api/pki/ca`);
        check(ca.status === 200, `CA download ${ca.status}`);
        fs.writeFileSync(path.join(work, "ca.pem"), await ca.text());
        for (const algorithm of opensslAlgorithms) {
          const { documentId } = created[algorithm];
          const cms = await fetch(`${BASE}/api/documents/${documentId}/export?part=cms`, { headers: { Cookie: viewer! } });
          const content = await fetch(`${BASE}/api/documents/${documentId}/export?part=content`, { headers: { Cookie: viewer! } });
          check(cms.status === 200 && content.status === 200, `${algorithm} export ${cms.status}/${content.status}`);
          fs.writeFileSync(path.join(work, `${algorithm}.p7s`), Buffer.from(await cms.arrayBuffer()));
          fs.writeFileSync(path.join(work, `${algorithm}.txt`), Buffer.from(await content.arrayBuffer()));
          const result = spawnSync("openssl", ["cms", "-verify", "-binary", "-inform", "DER", "-in", path.join(work, `${algorithm}.p7s`), "-content", path.join(work, `${algorithm}.txt`), "-CAfile", path.join(work, "ca.pem"), "-out", path.join(work, `${algorithm}.out`)], { encoding: "utf8" });
          check(result.status === 0 && /Verification successful/.test(`${result.stdout}${result.stderr}`), `${algorithm}: openssl cms -verify failed`);
        }
        return opensslAlgorithms.join(", ");
      });
    }

    await step("a key compromise makes the signature INVALID and is published in the CRL", async () => {
      const [algorithm] = ALGORITHMS;
      const { certificateId, documentId } = created[algorithm] ?? {};
      check(certificateId, "no certificate from the signing step");
      const revoked = await api(admin, "POST", `/api/certificates/${certificateId}/revoke`, { reason: "keyCompromise", comment: "E2E" });
      check(revoked.status === 200, `revoke: ${revoked.status}`);
      const verified = await api(verifier, "POST", `/api/documents/${documentId}/verify`);
      check(verified.json.result.outcome === "INVALID" && verified.json.result.reason === "CERTIFICATE_REVOKED", `after revocation: ${verified.json.result.outcome}/${verified.json.result.reason}`);
      const crl = await fetch(`${BASE}/api/pki/crl`);
      check(crl.status === 200 && crl.headers.get("content-type") === "application/pkix-crl", `CRL download ${crl.status}`);
      if (openssl) {
        const file = path.join(runDirectory, "e2e.crl");
        fs.writeFileSync(file, Buffer.from(await crl.arrayBuffer()));
        const text = spawnSync("openssl", ["crl", "-inform", "DER", "-in", file, "-noout", "-text"], { encoding: "utf8" }).stdout;
        check(/Key Compromise/.test(text), "the downloaded CRL does not list a key compromise");
      }
    });

    await step("cross-site and under-privileged requests are refused", async () => {
      check((await api(admin, "POST", "/api/audit/checkpoints", undefined, "https://evil.example")).status === 403, "cross-site POST was not refused");
      check((await api(viewer, "POST", "/api/certificates", { algorithm: ALGORITHMS[0] })).status === 403, "viewer could issue a certificate");
      check((await api(signer, "POST", "/api/anchoring/batches")).status === 403, "signer could anchor");
      check((await api(null, "GET", "/api/documents")).status === 401, "unauthenticated document list was allowed");
    });

    await step("the audit log verifies, and a signed checkpoint is created and reconciled", async () => {
      const before = await api(verifier, "POST", "/api/audit/verify");
      check(before.json.result.valid === true, `audit before checkpoint: ${before.json.result.explanation}`);
      const checkpoint = await api(admin, "POST", "/api/audit/checkpoints");
      check(checkpoint.status === 201 && checkpoint.json.checkpoint.timestamped, `checkpoint: ${checkpoint.status}`);
      const after = await api(verifier, "POST", "/api/audit/verify");
      check(after.json.result.valid === true && after.json.result.checkpoints.length === 1, `audit after checkpoint: ${after.json.result.explanation}`);
      return `${after.json.result.chain.entriesChecked} entries`;
    });

    await step("pending commitments anchor on the local chain and an anchor verifies", async () => {
      const anchored = await api(admin, "POST", "/api/anchoring/batches");
      check(anchored.status === 201, `anchor: ${anchored.status} ${anchored.json?.error ?? ""}`);
      const leaf = await database.anchorLeaf.findFirst({ where: { batchId: anchored.json.batch.id, kind: "SIGNATURE" } });
      check(leaf, "no signature leaf in the batch");
      const verified = await api(viewer, "GET", `/api/anchoring/verify?kind=SIGNATURE&target=${leaf.targetId}`);
      check(verified.json.result.status === "VALID", `anchor verification: ${verified.json.result.status}`);
      return `${anchored.json.batch.leafCount} leaves in block ${anchored.json.batch.blockNumber}`;
    });

    await step("a Security Lab run holds and leaves the installation's data untouched", async () => {
      const run = await api(admin, "POST", "/api/security-lab", { scenario: "control-untouched" });
      check(run.status === 200, `security lab: ${run.status} ${run.json?.error ?? ""}`);
      check(run.json.run.result.outcome === "HELD" && run.json.run.production.untouched && run.json.run.sandboxRemoved, `lab: ${run.json.run.result.outcome}`);
    });

    await step("repeated failed logins are throttled, even for the correct password", async () => {
      for (let attempt = 1; attempt <= 5; attempt += 1) {
        check((await login("viewer@demo", `wrong-${attempt}`)).status === 401, `wrong password ${attempt} was not 401`);
      }
      const locked = await login("viewer@demo");
      check(locked.status === 429, `correct password after 5 failures returned ${locked.status}`);
    });

    await step("logout clears the session cookie", async () => {
      const response = await fetch(`${BASE}/api/auth/logout`, { method: "POST", headers: { Cookie: signer!, Origin: BASE } });
      check(response.status === 200 && /Max-Age=0/i.test(response.headers.get("set-cookie") ?? ""), "logout did not expire the cookie");
    });
  } finally {
    await database.$disconnect();
    await stop(server);
    await stop(chain);
  }

  await step("the development database was not touched", async () => {
    check(fingerprint(devDatabase) === devBefore, "prisma/dev.db changed during the E2E run");
    return devBefore ? "SHA-256 identical before and after" : "no development database present";
  });

  let removed = false;
  try {
    fs.rmSync(runDirectory, { recursive: true, force: true, maxRetries: 10, retryDelay: 300 });
    removed = !fs.existsSync(runDirectory);
  } catch {
    removed = false;
  }

  const failed = results.filter((result) => result.status === "FAIL");
  const report = {
    runId,
    passed: failed.length === 0,
    durationMs: Date.now() - started,
    finishedAt: new Date().toISOString(),
    runDirectoryRemoved: removed,
    results,
    serverLogTail: failed.length > 0 ? serverLog : null,
  };
  fs.mkdirSync(E2E_ROOT, { recursive: true });
  fs.writeFileSync(path.join(E2E_ROOT, "report.json"), `${JSON.stringify(report, null, 2)}\n`);

  const passed = results.filter((result) => result.status === "PASS").length;
  const skipped = results.filter((result) => result.status === "SKIPPED").length;
  console.log(
    `\n${report.passed ? "E2E PASSED" : "E2E FAILED"}: ${passed} passed, ${failed.length} failed, ${skipped} skipped in ${(report.durationMs / 1000).toFixed(1)} s; ` +
      `isolated installation ${removed ? "removed" : "NOT removed"}; report in ${path.relative(ROOT, path.join(E2E_ROOT, "report.json"))}`,
  );
  if (failed.length > 0 && serverLog) console.log(`\nServer log tail:\n${serverLog}`);
  process.exitCode = report.passed ? 0 : 1;
}

const invokedDirectly = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  });
}
