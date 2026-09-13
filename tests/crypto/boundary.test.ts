import fs from "node:fs";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { ALGORITHMS } from "@/lib/crypto/orchestrator";
import {
  ALGORITHM_LITERAL_ALLOWLIST,
  findBoundaryViolations,
} from "@/scripts/check-crypto-boundary";

const PROBE = path.join(process.cwd(), "lib", "documents", "__boundary_probe.ts");

afterEach(() => {
  fs.rmSync(PROBE, { force: true });
});

describe("CLAUDE.md Section 2 rule 2: no algorithm-specific code outside lib/crypto/", () => {
  it("finds no violations in the codebase", () => {
    const violations = findBoundaryViolations();
    const rendered = violations.map((v) => `${v.file}:${v.line} ${v.detail}`).join("\n");
    expect(rendered).toBe("");
  });

  it("catches a node:crypto signing primitive imported into another layer", () => {
    fs.writeFileSync(
      PROBE,
      'import { createSign } from "node:crypto";\nexport const bad = createSign;\n',
    );
    expect(findBoundaryViolations()).toContainEqual(
      expect.objectContaining({ detail: expect.stringContaining("createSign") }),
    );
  });

  it("catches @noble imported into another layer", () => {
    fs.writeFileSync(PROBE, 'import * as ed from "@noble/ed25519";\nexport const bad = ed;\n');
    expect(findBoundaryViolations()).toContainEqual(
      expect.objectContaining({ detail: expect.stringContaining("@noble/ed25519") }),
    );
  });

  it("catches a namespace import that reaches a forbidden member", () => {
    fs.writeFileSync(
      PROBE,
      'import crypto from "node:crypto";\nexport const bad = () => crypto.createHash("sha256");\n',
    );
    expect(findBoundaryViolations()).toContainEqual(
      expect.objectContaining({ detail: expect.stringContaining("createHash") }),
    );
  });

  it("still allows non-cryptographic node:crypto helpers such as randomBytes", () => {
    fs.writeFileSync(
      PROBE,
      'import { randomBytes } from "node:crypto";\nexport const ok = () => randomBytes(16);\n',
    );
    expect(findBoundaryViolations()).toEqual([]);
  });
});

describe("algorithm branching outside lib/crypto", () => {
  it.each(["'", '"', "`"])("catches a registered algorithm named in a %s-quoted literal", (quote) => {
    const algorithm = ALGORITHMS[0];
    fs.writeFileSync(
      PROBE,
      `export function special(algorithm: string) {\n  return algorithm === ${quote}${algorithm}${quote};\n}\n`,
    );
    expect(findBoundaryViolations()).toContainEqual(
      expect.objectContaining({
        file: "lib/documents/__boundary_probe.ts",
        line: 2,
        detail: expect.stringContaining(`"${algorithm}"`),
      }),
    );
  });

  it("catches every registered algorithm, since the identifiers come from the registry", () => {
    fs.writeFileSync(
      PROBE,
      ALGORITHMS.map((algorithm, index) => `export const a${index} = "${algorithm}";`).join("\n"),
    );
    const flagged = findBoundaryViolations().filter(
      (violation) => violation.file === "lib/documents/__boundary_probe.ts",
    );
    expect(flagged).toHaveLength(ALGORITHMS.length);
  });

  it("does not flag prose that merely mentions an algorithm family", () => {
    fs.writeFileSync(PROBE, 'export const label = "Signed under RSA-PSS 3072 or ECDSA P-256";\n');
    expect(findBoundaryViolations()).toEqual([]);
  });

  it("keeps the allowlist to documented policy files that exist", () => {
    for (const [file, reason] of Object.entries(ALGORITHM_LITERAL_ALLOWLIST)) {
      expect(fs.existsSync(path.join(process.cwd(), file))).toBe(true);
      expect(reason.length).toBeGreaterThan(20);
    }
    expect(Object.keys(ALGORITHM_LITERAL_ALLOWLIST)).toEqual(["lib/pki/policy.ts"]);
  });
});
