// Committed evidence must not change silently: every file under docs/evidence is listed in the
// manifest with the digest it had when the manifest was generated.
import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { EVIDENCE_ROOT, MANIFEST, evidenceFiles, normalisedDigest } from "@/scripts/evidence-manifest";

describe("the evidence manifest", () => {
  it("lists every evidence file exactly once, with its current digest", () => {
    expect(fs.existsSync(MANIFEST), "run npm run evidence:manifest").toBe(true);
    const manifest = JSON.parse(fs.readFileSync(MANIFEST, "utf8")) as { files: { path: string; sha256: string; bytes: number }[] };
    const onDisk = evidenceFiles().map((file) => path.relative(EVIDENCE_ROOT, file).split(path.sep).join("/"));

    expect(manifest.files.map((entry) => entry.path).sort()).toEqual(onDisk);
    for (const entry of manifest.files) {
      expect(normalisedDigest(path.join(EVIDENCE_ROOT, entry.path)), entry.path).toEqual({ sha256: entry.sha256, bytes: entry.bytes });
    }
  });
});
