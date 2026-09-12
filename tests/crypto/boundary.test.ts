import fs from "node:fs";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { findBoundaryViolations } from "@/scripts/check-crypto-boundary";

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
