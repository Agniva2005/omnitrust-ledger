// Master-key custody for an installation (lib/crypto/key-custody.ts).
//
//   npm run key:custody -- status
//   npm run key:custody -- protect --method passphrase --yes
//   npm run key:custody -- protect --method dpapi --yes
//
// `protect` rewraps the key named by MASTER_KEY_PATH (default storage/keys/master.key). The key
// itself does not change, so every encrypted private key and document stays readable.
// - A new passphrase is read from OMNITRUST_NEW_MASTER_PASSPHRASE, never from the command line.
// - If the file is already passphrase-protected, the current passphrase comes from
//   OMNITRUST_MASTER_PASSPHRASE.
// - The new file is unwrapped and compared with the key before it replaces the old one.
//
// Losing the passphrase, or the Windows user profile that protects a DPAPI file, makes every private
// key and document of the installation unreadable. Back up accordingly before running `protect`.
import fs from "node:fs";
import path from "node:path";
import {
  MIN_PASSPHRASE_LENGTH,
  PASSPHRASE_VARIABLE,
  inspectMasterKey,
  loadMasterKey,
  wrapWithDpapi,
  wrapWithPassphrase,
  writeMasterKeyFile,
} from "../lib/crypto/key-custody";

const NEW_PASSPHRASE_VARIABLE = "OMNITRUST_NEW_MASTER_PASSPHRASE";
const keyPath = path.resolve(process.env.MASTER_KEY_PATH ?? "./storage/keys/master.key");

const DESCRIPTIONS = {
  plaintext: "plaintext file: anyone who can copy it can decrypt every private key and document",
  passphrase: `wrapped with AES-256-GCM under a scrypt-derived key; the application needs ${PASSPHRASE_VARIABLE} in its environment`,
  dpapi: "protected by Windows DPAPI for the current Windows user account",
} as const;

function argument(flag: string): string | null {
  const index = process.argv.indexOf(flag);
  return index === -1 ? null : process.argv[index + 1] ?? null;
}

function fail(message: string): never {
  console.error(message);
  process.exit(1);
}

function main() {
  const command = process.argv[2];
  const current = inspectMasterKey(keyPath);
  if (!current) fail(`No master key at ${keyPath}. Run npm run setup first.`);

  if (command === "status" || command === undefined) {
    console.log(`${keyPath}\n  ${DESCRIPTIONS[current.protection]}`);
    console.log("  In every case the key is a local file, not an HSM or KMS.");
    return;
  }

  if (command !== "protect") fail("Usage: npm run key:custody -- status | protect --method passphrase|dpapi --yes");

  const method = argument("--method");
  if (method !== "passphrase" && method !== "dpapi") fail("Choose --method passphrase or --method dpapi.");
  if (!process.argv.includes("--yes")) {
    fail("This replaces the key file. Back up what is needed to recover it (the passphrase, or the Windows profile), then re-run with --yes.");
  }

  const key = loadMasterKey(keyPath);
  let contents: string;
  let newPassphrase: string | undefined;
  if (method === "passphrase") {
    newPassphrase = process.env[NEW_PASSPHRASE_VARIABLE];
    if (!newPassphrase || newPassphrase.length < MIN_PASSPHRASE_LENGTH) {
      fail(`Set ${NEW_PASSPHRASE_VARIABLE} to a passphrase of at least ${MIN_PASSPHRASE_LENGTH} characters.`);
    }
    contents = wrapWithPassphrase(key, newPassphrase);
  } else {
    contents = wrapWithDpapi(key);
  }

  const candidate = `${keyPath}.candidate`;
  writeMasterKeyFile(candidate, contents);
  const roundTrip = loadMasterKey(candidate, { passphrase: newPassphrase ?? null });
  if (!roundTrip.equals(key)) fail("The rewrapped key did not unwrap to the same key; the original file was left unchanged.");
  writeMasterKeyFile(keyPath, contents);
  // The candidate held only wrapped material; remove it now the real file is replaced.
  fs.rmSync(candidate, { force: true });

  console.log(`Rewrapped ${keyPath}: now ${DESCRIPTIONS[method]}.`);
  if (method === "passphrase") console.log(`Start the application with ${PASSPHRASE_VARIABLE} set in its environment (not in .env, which sits beside the key).`);
}

main();
