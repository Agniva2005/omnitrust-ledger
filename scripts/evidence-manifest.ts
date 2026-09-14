// Writes docs/evidence/manifest.json: every committed evidence file with its SHA-256, size and the
// provenance it records about itself (when it was generated, from which commit, with which seed and
// sample size). tests/ci/evidence-manifest.test.ts fails if a file is added, removed or edited
// without regenerating the manifest.
//
//   npm run evidence:manifest
//
// Hashes are taken over the file with line endings normalised to LF, so a checkout that converts
// line endings does not look like an edit.
import fs from "node:fs";
import path from "node:path";
import { sha256Hex } from "../lib/crypto/hash";

export const EVIDENCE_ROOT = path.join(process.cwd(), "docs", "evidence");
export const MANIFEST = path.join(EVIDENCE_ROOT, "manifest.json");

export function evidenceFiles(directory = EVIDENCE_ROOT): string[] {
  if (!fs.existsSync(directory)) return [];
  return fs
    .readdirSync(directory, { withFileTypes: true })
    .flatMap((entry) => {
      const full = path.join(directory, entry.name);
      if (entry.isDirectory()) return evidenceFiles(full);
      return /\.(json|md)$/.test(entry.name) && full !== MANIFEST ? [full] : [];
    })
    .sort();
}

export function normalisedDigest(file: string): { sha256: string; bytes: number } {
  const text = fs.readFileSync(file, "utf8").replace(/\r\n/g, "\n");
  const bytes = Buffer.from(text, "utf8");
  return { sha256: sha256Hex(bytes), bytes: bytes.length };
}

function provenance(file: string): Record<string, unknown> {
  if (!file.endsWith(".json")) return { kind: "report" };
  const data = JSON.parse(fs.readFileSync(file, "utf8"));
  const kind = data.comparisons && data.algorithms ? "migration-study" : Array.isArray(data.results) ? "security-lab-evaluation" : data.algorithms?.[0]?.payloads ? "benchmark" : "other";
  return {
    kind,
    generatedAt: data.generatedAt ?? null,
    gitCommit: data.environment?.gitCommit ?? null,
    gitTreeDirty: data.environment?.gitTreeDirty ?? null,
    cpu: data.environment?.cpu ?? null,
    seed: data.parameters?.seed ?? null,
    iterations: data.parameters?.iterations ?? null,
    caAlgorithm: data.trustServices?.ca?.displayName ?? null,
    tsaAlgorithm: data.trustServices?.tsa?.displayName ?? null,
  };
}

export function buildManifest() {
  return {
    description: "Committed evidence files, with digests over LF-normalised content. Regenerate with npm run evidence:manifest.",
    files: evidenceFiles().map((file) => ({
      path: path.relative(EVIDENCE_ROOT, file).split(path.sep).join("/"),
      ...normalisedDigest(file),
      ...provenance(file),
    })),
  };
}

if (process.argv[1]?.endsWith("evidence-manifest.ts")) {
  fs.mkdirSync(EVIDENCE_ROOT, { recursive: true });
  const manifest = buildManifest();
  fs.writeFileSync(MANIFEST, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(`Wrote ${path.relative(process.cwd(), MANIFEST)} covering ${manifest.files.length} files.`);
}
