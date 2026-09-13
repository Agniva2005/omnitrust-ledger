// Guards the documentation against drifting from the code: every `npm run` command the README
// or demo script names must exist, every seeded filename they name must be one the fixtures
// actually create, and every local file they link to must exist.
import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { ALGORITHMS } from "@/lib/crypto/orchestrator";
import { signedSampleFor } from "@/prisma/fixtures";

const ROOT = process.cwd();
const DOCUMENTS = ["README.md", "DEMO_SCRIPT.md", "docs/final-implementation-report.md"];
const read = (file: string) => fs.readFileSync(path.join(ROOT, file), "utf8");

describe("documentation claims", () => {
  it("names only npm scripts that exist", () => {
    const scripts = Object.keys(JSON.parse(read("package.json")).scripts);
    for (const document of DOCUMENTS) {
      const named = [...read(document).matchAll(/npm run ([a-z][a-z0-9:-]*)/g)].map((match) => match[1]);
      for (const script of named) expect(scripts, `${document} names "npm run ${script}"`).toContain(script);
    }
  });

  it("names seeded sample documents exactly as the fixtures create them", () => {
    const seeded = new Set([
      ...ALGORITHMS.map((algorithm, index) => signedSampleFor(algorithm, index).filename),
      "draft-policy.md",
      "invoice-tampered.txt",
    ]);
    for (const document of ["README.md", "DEMO_SCRIPT.md"]) {
      const named = [...read(document).matchAll(/`([a-z][a-z0-9-]*\.(?:txt|md))`/g)]
        .map((match) => match[1])
        .filter((name) => !/^(readme|demo_script|progress|claude)\.md$/i.test(name));
      for (const filename of named) expect([...seeded], `${document} names ${filename}`).toContain(filename);
    }
  });

  it("links only to local files that exist", () => {
    for (const document of DOCUMENTS) {
      const directory = path.dirname(path.join(ROOT, document));
      const links = [...read(document).matchAll(/\]\(((?!https?:|#|mailto:)[^)#\s]+)(?:#[^)]*)?\)/g)].map((match) => match[1]);
      for (const link of links) expect(fs.existsSync(path.resolve(directory, link)), `${document} links to ${link}`).toBe(true);
    }
  });

  it("does not repeat limitations the code has since removed", () => {
    const readme = read("README.md");
    expect(readme).not.toMatch(/no CRL or OCSP/i);
    expect(readme).not.toMatch(/No rate limiting/i);
    expect(readme).not.toMatch(/Node\.js 20 or newer/);
  });
});
