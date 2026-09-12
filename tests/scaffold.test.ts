import { describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";

const root = process.cwd();

describe("Section 3 folder map", () => {
  const required = [
    "lib/auth/session.ts",
    "lib/auth/rbac.ts",
    "lib/documents/lifecycle.ts",
    "lib/documents/storage.ts",
    "lib/documents/service.ts",
    "lib/crypto/types.ts",
    "lib/crypto/orchestrator.ts",
    "lib/crypto/providers/rsa.ts",
    "lib/crypto/providers/ecdsa.ts",
    "lib/crypto/providers/eddsa.ts",
    "lib/pki/ca.ts",
    "lib/pki/certificates.ts",
    "lib/pki/keys.ts",
    "lib/pki/validation.ts",
    "lib/audit/log.ts",
    "lib/audit/integrity.ts",
    "prisma/schema.prisma",
  ];

  it.each(required)("has %s", (relative) => {
    expect(fs.existsSync(path.join(root, relative))).toBe(true);
  });
});

describe(".env.example", () => {
  it("documents every variable the app reads", () => {
    const example = fs.readFileSync(path.join(root, ".env.example"), "utf8");
    for (const key of ["DATABASE_URL", "JWT_SECRET", "MASTER_KEY_PATH", "STORAGE_ROOT"]) {
      expect(example).toContain(key);
    }
  });

  it("is committed while .env is ignored", () => {
    const gitignore = fs.readFileSync(path.join(root, ".gitignore"), "utf8");
    expect(gitignore.split(/\r?\n/)).toContain(".env");
    expect(gitignore).not.toContain(".env.example");
  });
});
