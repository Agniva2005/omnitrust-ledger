// Security Lab: disposable sandboxes.
//
// Each run gets a fresh directory under <lab root>/runs/<run id> holding a copy of a
// pre-migrated template database, its own document storage and its own random master key.
// The scenario runs in a separate process whose environment points only there, so the
// application's own database, blobs and keys are not reachable from it at all. The run
// directory is deleted afterwards.
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { sha256Hex } from "@/lib/crypto/hash";
import { prismaCliQuiet } from "@/lib/prisma-cli";
import type { ScenarioResult } from "@/lib/security-lab/catalog";
import { labRoot } from "@/lib/security-lab/guard";
import { RESULT_MARKER } from "@/lib/security-lab/protocol";

const RUN_TIMEOUT_MS = 180_000;

const sqliteUrl = (file: string) => `file:${file.split(path.sep).join("/")}`;

function migrationsFingerprint(): string {
  const root = path.join(process.cwd(), "prisma", "migrations");
  const parts = fs
    .readdirSync(root, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort()
    .map((name) => `${name}:${sha256Hex(fs.readFileSync(path.join(root, name, "migration.sql")))}`);
  return sha256Hex(parts.join("\n"));
}

/** Builds (or rebuilds after a schema change) the migrated template every run copies. */
export function ensureTemplate(): string {
  const root = labRoot();
  const template = path.join(root, "template.db");
  const stamp = path.join(root, "template.fingerprint");
  const fingerprint = migrationsFingerprint();

  if (fs.existsSync(template) && fs.existsSync(stamp) && fs.readFileSync(stamp, "utf8") === fingerprint) return template;

  fs.mkdirSync(root, { recursive: true });
  fs.rmSync(template, { force: true });
  prismaCliQuiet(["migrate", "deploy"], { DATABASE_URL: sqliteUrl(template) });
  fs.writeFileSync(stamp, fingerprint);
  return template;
}

export type SandboxRun = {
  result: ScenarioResult;
  runId: string;
  durationMs: number;
  /** Whether the sandbox directory was deleted after the run. */
  sandboxRemoved: boolean;
};

/** A document from the application to use as the scenario's subject, already decrypted. */
export type SandboxSubject = { bytes: Buffer; filename: string; mimeType: string };

export async function runScenarioInSandbox(id: string, chosen?: SandboxSubject): Promise<SandboxRun> {
  const template = ensureTemplate();
  const runId = `${Date.now()}-${randomBytes(4).toString("hex")}`;
  const directory = path.join(labRoot(), "runs", runId);
  const database = path.join(directory, "lab.db");
  const storage = path.join(directory, "storage");
  const key = path.join(directory, "keys", "master.key");

  fs.mkdirSync(path.join(storage, "documents"), { recursive: true });
  fs.mkdirSync(path.dirname(key), { recursive: true });
  fs.copyFileSync(template, database);
  fs.writeFileSync(key, randomBytes(32).toString("base64"));

  // The child has its own master key and cannot read the application's blobs, so a chosen
  // document travels as plaintext in the run directory, deleted with the rest of the sandbox.
  const subjectFile = path.join(directory, "subject.bin");
  if (chosen) fs.writeFileSync(subjectFile, chosen.bytes);

  const started = Date.now();
  try {
    const output = await new Promise<string>((resolve, reject) => {
      const child = spawn(
        process.execPath,
        [path.join(process.cwd(), "node_modules", "tsx", "dist", "cli.mjs"), path.join(process.cwd(), "scripts", "security-lab-runner.ts"), id],
        {
          cwd: process.cwd(),
          stdio: ["ignore", "pipe", "pipe"],
          env: {
            ...process.env,
            DATABASE_URL: sqliteUrl(database),
            STORAGE_ROOT: storage,
            MASTER_KEY_PATH: key,
            JWT_SECRET: randomBytes(32).toString("hex"),
            SECURITY_LAB_ROOT: labRoot(),
            OMNITRUST_SECURITY_LAB: "1",
            ...(chosen
              ? {
                  SECURITY_LAB_SUBJECT: subjectFile,
                  SECURITY_LAB_SUBJECT_NAME: chosen.filename,
                  SECURITY_LAB_SUBJECT_TYPE: chosen.mimeType,
                }
              : {}),
            // Scenarios never anchor; make sure they could not reach a real chain if they tried.
            ANCHOR_RPC_URL: "http://127.0.0.1:9",
          },
        },
      );
      let stdout = "";
      child.stdout.on("data", (chunk) => {
        stdout += chunk;
      });
      child.stderr.on("data", () => undefined);
      const timer = setTimeout(() => {
        child.kill();
        reject(new Error("The Security Lab scenario timed out"));
      }, RUN_TIMEOUT_MS);
      child.on("error", (error) => {
        clearTimeout(timer);
        reject(error);
      });
      child.on("close", () => {
        clearTimeout(timer);
        resolve(stdout);
      });
    });

    const line = output.split(/\r?\n/).find((candidate) => candidate.startsWith(RESULT_MARKER));
    if (!line) throw new Error("The Security Lab scenario produced no result");
    const parsed = JSON.parse(line.slice(RESULT_MARKER.length)) as ScenarioResult | { refused: string };
    if ("refused" in parsed) throw new Error(`The Security Lab runner refused: ${parsed.refused}`);
    return { result: parsed, runId, durationMs: Date.now() - started, sandboxRemoved: removeRun(directory) };
  } catch (error) {
    removeRun(directory);
    throw error;
  }
}

function removeRun(directory: string): boolean {
  fs.rmSync(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  return !fs.existsSync(directory);
}
