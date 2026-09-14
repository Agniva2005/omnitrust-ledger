// Master-key custody: how the data-encryption key that protects every private key and document blob is
// itself stored. Local-first options only; none of them is an HSM or a KMS.
//
// - plaintext: the 32-byte key, base64, in a file. The original format, still what `npm run setup`
//   writes and what disposable installations (tests, Security Lab sandboxes, studies) use.
// - passphrase: the key wrapped with AES-256-GCM under a key derived from a passphrase with scrypt.
//   The file header (format, KDF and parameters, cipher) is authenticated as additional data.
// - dpapi: the key protected by Windows DPAPI for the current user account, through PowerShell's
//   ProtectedData class. The key travels over stdin and stdout, never on a command line.
//
// Wrapping changes only how the key is stored, never the key itself, so existing ciphertext stays
// readable after a change of custody. Error messages never include a passphrase or key material.
import { execFileSync } from "node:child_process";
import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export const MASTER_KEY_BYTES = 32;
/** Where the application reads a passphrase from. Set it in the process environment, not in .env beside the key. */
export const PASSPHRASE_VARIABLE = "OMNITRUST_MASTER_PASSPHRASE";
export const MIN_PASSPHRASE_LENGTH = 12;

const FORMAT = "omnitrust-master-key";
const IV_BYTES = 12;
const SALT_BYTES = 16;
/** OWASP's scrypt baseline is N=2^17, r=8, p=1. */
export const DEFAULT_SCRYPT_COST = { N: 2 ** 17, r: 8, p: 1 } as const;
const MIN_SCRYPT_N = 2 ** 14;
const SCRYPT_MAXMEM = 512 * 1024 * 1024;
/** Binds DPAPI blobs to this purpose: another application's DPAPI blob does not unprotect as a master key. */
const DPAPI_ENTROPY = Buffer.from("OmniTrust Ledger master key v1", "utf8");

export type Protection = "plaintext" | "passphrase" | "dpapi";
export type ScryptCost = { N: number; r: number; p: number };

export class KeyCustodyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "KeyCustodyError";
  }
}

type PassphraseEnvelope = {
  format: typeof FORMAT;
  version: 1;
  protection: "passphrase";
  kdf: { name: "scrypt"; N: number; r: number; p: number; salt: string };
  cipher: "aes-256-gcm";
  iv: string;
  tag: string;
  wrappedKey: string;
};

type DpapiEnvelope = { format: typeof FORMAT; version: 1; protection: "dpapi"; scope: "CurrentUser"; blob: string };

type Parsed = { protection: "plaintext"; key: Buffer } | PassphraseEnvelope | DpapiEnvelope;

function header(envelope: PassphraseEnvelope): Buffer {
  const { format, version, protection, kdf, cipher } = envelope;
  return Buffer.from(JSON.stringify({ format, version, protection, kdf, cipher }), "utf8");
}

function parse(contents: string, keyPath: string): Parsed {
  const text = contents.trim();
  if (!text.startsWith("{")) {
    const key = Buffer.from(text, "base64");
    if (key.length !== MASTER_KEY_BYTES) {
      throw new KeyCustodyError(`Master key at ${keyPath} must be ${MASTER_KEY_BYTES} bytes (base64-encoded), got ${key.length}`);
    }
    return { protection: "plaintext", key };
  }
  let envelope: { format?: unknown; version?: unknown; protection?: unknown };
  try {
    envelope = JSON.parse(text) as typeof envelope;
  } catch {
    throw new KeyCustodyError(`The master key file ${path.basename(keyPath)} is not valid JSON`);
  }
  if (envelope.format !== FORMAT || envelope.version !== 1) {
    throw new KeyCustodyError(`The master key file ${path.basename(keyPath)} has an unsupported format`);
  }
  if (envelope.protection === "passphrase" || envelope.protection === "dpapi") return envelope as PassphraseEnvelope | DpapiEnvelope;
  throw new KeyCustodyError(`The master key file ${path.basename(keyPath)} uses an unsupported protection`);
}

function assertCost({ N, r, p }: ScryptCost) {
  const valid =
    Number.isInteger(N) && N >= MIN_SCRYPT_N && N <= 2 ** 22 && (N & (N - 1)) === 0 &&
    Number.isInteger(r) && r >= 1 && r <= 32 &&
    Number.isInteger(p) && p >= 1 && p <= 16;
  if (!valid) throw new KeyCustodyError(`Unsupported scrypt parameters (N must be a power of two of at least ${MIN_SCRYPT_N})`);
}

function deriveKey(passphrase: string, salt: Buffer, cost: ScryptCost): Buffer {
  assertCost(cost);
  return scryptSync(passphrase.normalize("NFC"), salt, MASTER_KEY_BYTES, { ...cost, maxmem: SCRYPT_MAXMEM });
}

function dpapi(operation: "Protect" | "Unprotect", data: Buffer): Buffer {
  if (process.platform !== "win32") throw new KeyCustodyError("Windows DPAPI is only available on Windows");
  const script = [
    "$ErrorActionPreference = 'Stop'",
    "Add-Type -AssemblyName System.Security",
    "$data = [Convert]::FromBase64String([Console]::In.ReadToEnd().Trim())",
    `$entropy = [Convert]::FromBase64String('${DPAPI_ENTROPY.toString("base64")}')`,
    `$result = [Security.Cryptography.ProtectedData]::${operation}($data, $entropy, [Security.Cryptography.DataProtectionScope]::CurrentUser)`,
    "[Console]::Out.Write([Convert]::ToBase64String($result))",
  ].join("; ");
  let output: string;
  try {
    output = execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], {
      input: data.toString("base64"),
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
      timeout: 60_000,
    });
  } catch {
    throw new KeyCustodyError(
      operation === "Protect"
        ? "Windows DPAPI could not protect the master key"
        : "Windows DPAPI could not unprotect the master key: it belongs to another Windows user or machine, or the file was altered",
    );
  }
  return Buffer.from(output.trim(), "base64");
}

/** Which protection a key file uses, read from the file alone. Null when there is no file. */
export function inspectMasterKey(keyPath: string): { protection: Protection } | null {
  if (!fs.existsSync(keyPath)) return null;
  return { protection: parse(fs.readFileSync(keyPath, "utf8"), keyPath).protection };
}

export type LoadOptions = {
  /** The passphrase for a passphrase-wrapped file. Undefined reads PASSPHRASE_VARIABLE; null means none is available. */
  passphrase?: string | null;
};

/** Reads and, where needed, unwraps the master key. */
export function loadMasterKey(keyPath: string, options: LoadOptions = {}): Buffer {
  const parsed = parse(fs.readFileSync(keyPath, "utf8"), keyPath);

  if (parsed.protection === "plaintext") return parsed.key;

  if (parsed.protection === "dpapi") {
    const key = dpapi("Unprotect", Buffer.from(parsed.blob, "base64"));
    if (key.length !== MASTER_KEY_BYTES) throw new KeyCustodyError("Windows DPAPI returned a key of the wrong length");
    return key;
  }

  const passphrase = options.passphrase === undefined ? process.env[PASSPHRASE_VARIABLE] : options.passphrase;
  if (!passphrase) {
    throw new KeyCustodyError(`The master key is passphrase-protected; set ${PASSPHRASE_VARIABLE} in the environment of the process that needs it`);
  }
  const { kdf } = parsed;
  const wrappingKey = deriveKey(passphrase, Buffer.from(kdf.salt, "base64"), { N: kdf.N, r: kdf.r, p: kdf.p });
  try {
    const decipher = createDecipheriv("aes-256-gcm", wrappingKey, Buffer.from(parsed.iv, "base64"));
    decipher.setAAD(header(parsed));
    decipher.setAuthTag(Buffer.from(parsed.tag, "base64"));
    const key = Buffer.concat([decipher.update(Buffer.from(parsed.wrappedKey, "base64")), decipher.final()]);
    if (key.length !== MASTER_KEY_BYTES) throw new Error("wrong length");
    return key;
  } catch {
    throw new KeyCustodyError("The master key could not be unwrapped: the passphrase is wrong or the key file was altered");
  }
}

/** A passphrase-wrapped key file's contents. */
export function wrapWithPassphrase(key: Buffer, passphrase: string, cost: ScryptCost = DEFAULT_SCRYPT_COST): string {
  if (key.length !== MASTER_KEY_BYTES) throw new KeyCustodyError(`The master key must be ${MASTER_KEY_BYTES} bytes`);
  if (passphrase.length < MIN_PASSPHRASE_LENGTH) throw new KeyCustodyError(`The passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters`);
  const salt = randomBytes(SALT_BYTES);
  const iv = randomBytes(IV_BYTES);
  const envelope: PassphraseEnvelope = {
    format: FORMAT,
    version: 1,
    protection: "passphrase",
    kdf: { name: "scrypt", N: cost.N, r: cost.r, p: cost.p, salt: salt.toString("base64") },
    cipher: "aes-256-gcm",
    iv: iv.toString("base64"),
    tag: "",
    wrappedKey: "",
  };
  const cipher = createCipheriv("aes-256-gcm", deriveKey(passphrase, salt, cost), iv);
  cipher.setAAD(header(envelope));
  envelope.wrappedKey = Buffer.concat([cipher.update(key), cipher.final()]).toString("base64");
  envelope.tag = cipher.getAuthTag().toString("base64");
  return `${JSON.stringify(envelope, null, 2)}\n`;
}

/** A DPAPI-protected key file's contents, bound to the current Windows user account. */
export function wrapWithDpapi(key: Buffer): string {
  if (key.length !== MASTER_KEY_BYTES) throw new KeyCustodyError(`The master key must be ${MASTER_KEY_BYTES} bytes`);
  const envelope: DpapiEnvelope = { format: FORMAT, version: 1, protection: "dpapi", scope: "CurrentUser", blob: dpapi("Protect", key).toString("base64") };
  return `${JSON.stringify(envelope, null, 2)}\n`;
}

/** Replaces a key file atomically: written beside it, then renamed over it. */
export function writeMasterKeyFile(keyPath: string, contents: string) {
  const temporary = `${keyPath}.${randomBytes(4).toString("hex")}.tmp`;
  fs.mkdirSync(path.dirname(keyPath), { recursive: true });
  fs.writeFileSync(temporary, contents, { mode: 0o600 });
  fs.renameSync(temporary, keyPath);
}
