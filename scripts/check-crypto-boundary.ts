// Enforces CLAUDE.md Section 2 rule 2: no algorithm-specific code outside /lib/crypto/.
//
// Two kinds of violation are detected:
//   1. Imports of cryptographic libraries or primitives into any other layer.
//   2. Algorithm identifiers written as string literals in any other layer. Import scanning
//      alone cannot see a comparison against an algorithm's name; this can, because the identifiers are
//      read from the provider registry rather than hard-coded here.
//
// Run directly (`npm run check:boundary`) or via tests/crypto/boundary.test.ts, which
// fails the suite on any violation.
//
// tests/ is not scanned on purpose: the test suite deliberately reaches for a second,
// independent implementation of each algorithm (node:crypto and @noble/curves) to
// cross-check the providers, which is the opposite of a layering violation.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ALGORITHMS } from "../lib/crypto/orchestrator";

const SCANNED_ROOTS = ["app", "lib", "components", "prisma", "scripts"];
const SCANNED_ROOT_FILES = ["middleware.ts"];

/** Directories permitted to contain algorithm-specific code, relative to the repo root. */
const CRYPTO_LAYER = ["lib/crypto"];

/** X.509 encoding belongs to the PKI layer; the algorithm parameters it passes in come
 *  from the orchestrator, so it never names an algorithm itself. */
const X509_ALLOWED = ["lib/crypto", "lib/pki"];

/**
 * Files outside lib/crypto allowed to name an algorithm, each with the reason. Keep this
 * list short: every entry is a place where adding or removing a provider could require an
 * edit outside the crypto layer.
 */
export const ALGORITHM_LITERAL_ALLOWLIST: Record<string, string> = {
  "lib/pki/policy.ts":
    "Chooses which registered algorithm the local CA signs with: a policy value, not algorithm-specific logic.",
};

/** node:crypto exports that perform or configure signature/cipher/digest operations. */
const FORBIDDEN_NODE_CRYPTO_SYMBOLS = [
  "constants",
  "createCipheriv",
  "createDecipheriv",
  "createECDH",
  "createHash",
  "createHmac",
  "createPrivateKey",
  "createPublicKey",
  "createSecretKey",
  "createSign",
  "createVerify",
  "diffieHellman",
  "generateKey",
  "generateKeyPair",
  "generateKeyPairSync",
  "generateKeySync",
  "hash",
  "privateDecrypt",
  "privateEncrypt",
  "publicDecrypt",
  "publicEncrypt",
  "sign",
  "subtle",
  "verify",
  "webcrypto",
];

export type Violation = {
  file: string;
  line: number;
  detail: string;
};

function listFiles(root: string): string[] {
  const absolute = path.join(process.cwd(), root);
  if (!fs.existsSync(absolute)) return [];

  const files: string[] = [];
  const walk = (dir: string) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name === "node_modules" || entry.name.startsWith(".")) continue;
        walk(full);
      } else if (/\.(ts|tsx)$/.test(entry.name)) {
        files.push(path.relative(process.cwd(), full).split(path.sep).join("/"));
      }
    }
  };
  walk(absolute);
  return files;
}

function isWithin(file: string, directories: string[]): boolean {
  return directories.some((directory) => file.startsWith(`${directory}/`));
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function findBoundaryViolations(): Violation[] {
  const violations: Violation[] = [];
  const files = [
    ...SCANNED_ROOTS.flatMap(listFiles),
    ...SCANNED_ROOT_FILES.filter((file) => fs.existsSync(path.join(process.cwd(), file))),
  ];

  const literalPatterns = ALGORITHMS.map((algorithm) => ({
    algorithm,
    pattern: new RegExp(`(["'\`])${escapeRegExp(algorithm)}\\1`),
  }));

  for (const file of files) {
    const inCryptoLayer = isWithin(file, CRYPTO_LAYER);
    const literalAllowed = inCryptoLayer || file in ALGORITHM_LITERAL_ALLOWLIST;
    const lines = fs.readFileSync(path.join(process.cwd(), file), "utf8").split(/\r?\n/);

    lines.forEach((line, index) => {
      const lineNumber = index + 1;
      const moduleMatch = line.match(
        /(?:from|import|require)\s*\(?\s*["']([^"']+)["']/,
      );
      const moduleName = moduleMatch?.[1];

      if (!literalAllowed) {
        for (const { algorithm, pattern } of literalPatterns) {
          if (pattern.test(line)) {
            violations.push({
              file,
              line: lineNumber,
              detail: `names the algorithm "${algorithm}" as a literal; resolve algorithms through the orchestrator instead`,
            });
          }
        }
      }

      if (moduleName?.startsWith("@noble/") && !inCryptoLayer) {
        violations.push({
          file,
          line: lineNumber,
          detail: `imports ${moduleName}; signature algorithms belong in lib/crypto/`,
        });
      }

      if (moduleName === "@peculiar/x509" && !isWithin(file, X509_ALLOWED)) {
        violations.push({
          file,
          line: lineNumber,
          detail: `imports @peculiar/x509; certificate encoding belongs in ${X509_ALLOWED.join(" or ")}/`,
        });
      }

      if ((moduleName === "node:crypto" || moduleName === "crypto") && !inCryptoLayer) {
        // A default/namespace import hides which symbols are used, so treat the
        // members accessed on it as the import list too.
        const named = line.match(/import\s*\{([^}]*)\}/)?.[1] ?? "";
        const namespaced = /import\s+(?:\*\s+as\s+)?(\w+)\s+from/.exec(line)?.[1];
        const usedSymbols = named
          .split(",")
          .map((entry) => entry.split(/\s+as\s+/)[0].trim())
          .filter(Boolean);

        for (const symbol of usedSymbols) {
          if (FORBIDDEN_NODE_CRYPTO_SYMBOLS.includes(symbol)) {
            violations.push({
              file,
              line: lineNumber,
              detail: `imports { ${symbol} } from node:crypto; cryptographic primitives belong in lib/crypto/`,
            });
          }
        }

        if (namespaced) {
          const body = lines.join("\n");
          for (const symbol of FORBIDDEN_NODE_CRYPTO_SYMBOLS) {
            if (new RegExp(`\\b${namespaced}\\.${symbol}\\b`).test(body)) {
              violations.push({
                file,
                line: lineNumber,
                detail: `uses ${namespaced}.${symbol}() from node:crypto; cryptographic primitives belong in lib/crypto/`,
              });
            }
          }
        }
      }
    });
  }

  return violations;
}

function main() {
  const violations = findBoundaryViolations();
  if (violations.length === 0) {
    console.log(
      "Crypto boundary OK: no algorithm-specific imports or algorithm literals outside lib/crypto/.",
    );
    return;
  }
  console.error(`Crypto boundary violated (${violations.length}):\n`);
  for (const violation of violations) {
    console.error(`  ${violation.file}:${violation.line} - ${violation.detail}`);
  }
  process.exitCode = 1;
}

const invokedDirectly =
  process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) main();
