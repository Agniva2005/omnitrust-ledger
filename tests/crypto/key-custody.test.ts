// Master-key custody. A wrapped key file must give back exactly the key it wraps, only to the holder
// of the passphrase or the Windows account; refuse a wrong or missing passphrase and an altered file
// without revealing either; and leave ciphertext written before wrapping readable afterwards.
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  KeyCustodyError,
  PASSPHRASE_VARIABLE,
  inspectMasterKey,
  loadMasterKey,
  wrapWithDpapi,
  wrapWithPassphrase,
  writeMasterKeyFile,
} from "@/lib/crypto/key-custody";
import { decrypt, encrypt, resetMasterKeyCache } from "@/lib/crypto/symmetric";

const DIRECTORY = path.join(process.cwd(), "storage", "test", "key-custody");
// The minimum accepted cost keeps the suite fast; the default for real files is N = 2^17.
const FAST = { N: 2 ** 14, r: 8, p: 1 };
const PASSPHRASE = "correct horse battery staple";

function file(name: string, contents: string) {
  const location = path.join(DIRECTORY, name);
  writeMasterKeyFile(location, contents);
  return location;
}

function errorOf(action: () => unknown): Error {
  try {
    action();
  } catch (error) {
    return error as Error;
  }
  throw new Error("expected the action to throw");
}

beforeAll(() => fs.mkdirSync(DIRECTORY, { recursive: true }));
afterAll(() => {
  delete process.env[PASSPHRASE_VARIABLE];
  fs.rmSync(DIRECTORY, { recursive: true, force: true });
});

describe("a plaintext key file", () => {
  it("loads as the key it holds, and is reported as plaintext", () => {
    const key = randomBytes(32);
    const location = file("plain.key", key.toString("base64"));
    expect(loadMasterKey(location).equals(key)).toBe(true);
    expect(inspectMasterKey(location)).toEqual({ protection: "plaintext" });
  });

  it("refuses a key of the wrong length", () => {
    expect(() => loadMasterKey(file("short.key", randomBytes(16).toString("base64")))).toThrow(KeyCustodyError);
  });
});

describe("a passphrase-wrapped key file", () => {
  const key = randomBytes(32);

  it("gives back exactly the wrapped key, and does not contain it", () => {
    const contents = wrapWithPassphrase(key, PASSPHRASE, FAST);
    const location = file("wrapped.key", contents);
    expect(loadMasterKey(location, { passphrase: PASSPHRASE }).equals(key)).toBe(true);
    expect(inspectMasterKey(location)).toEqual({ protection: "passphrase" });
    expect(contents).not.toContain(key.toString("base64"));
    expect(contents).not.toContain(key.toString("hex"));
  });

  it("uses a fresh salt and nonce each time", () => {
    const first = wrapWithPassphrase(key, PASSPHRASE, FAST);
    const second = wrapWithPassphrase(key, PASSPHRASE, FAST);
    expect(first).not.toBe(second);
    expect(loadMasterKey(file("second.key", second), { passphrase: PASSPHRASE }).equals(key)).toBe(true);
  });

  it("refuses a wrong passphrase without echoing it", () => {
    const error = errorOf(() => loadMasterKey(file("wrong.key", wrapWithPassphrase(key, PASSPHRASE, FAST)), { passphrase: "a guessed passphrase" }));
    expect(error).toBeInstanceOf(KeyCustodyError);
    expect(error.message).not.toContain("a guessed passphrase");
    expect(error.message).not.toContain(PASSPHRASE);
  });

  it("says which variable to set when no passphrase is available", () => {
    delete process.env[PASSPHRASE_VARIABLE];
    const location = file("missing.key", wrapWithPassphrase(key, PASSPHRASE, FAST));
    expect(() => loadMasterKey(location)).toThrow(new RegExp(PASSPHRASE_VARIABLE));
    expect(() => loadMasterKey(location, { passphrase: null })).toThrow(KeyCustodyError);
    process.env[PASSPHRASE_VARIABLE] = PASSPHRASE;
    expect(loadMasterKey(location).equals(key)).toBe(true);
    delete process.env[PASSPHRASE_VARIABLE];
  });

  it("detects an altered wrapped key, tag or header", () => {
    const envelope = JSON.parse(wrapWithPassphrase(key, PASSPHRASE, FAST));
    const flip = (value: string) => {
      const bytes = Buffer.from(value, "base64");
      bytes[0] ^= 0x01;
      return bytes.toString("base64");
    };
    for (const altered of [
      { ...envelope, wrappedKey: flip(envelope.wrappedKey) },
      { ...envelope, tag: flip(envelope.tag) },
      { ...envelope, kdf: { ...envelope.kdf, salt: flip(envelope.kdf.salt) } },
    ]) {
      expect(() => loadMasterKey(file("altered.key", JSON.stringify(altered)), { passphrase: PASSPHRASE })).toThrow(KeyCustodyError);
    }
  });

  it("refuses scrypt parameters weaker than the minimum, and short passphrases", () => {
    const envelope = JSON.parse(wrapWithPassphrase(key, PASSPHRASE, FAST));
    const weakened = { ...envelope, kdf: { ...envelope.kdf, N: 2 ** 10 } };
    expect(() => loadMasterKey(file("weak.key", JSON.stringify(weakened)), { passphrase: PASSPHRASE })).toThrow(/scrypt parameters/);
    expect(() => wrapWithPassphrase(key, "short", FAST)).toThrow(KeyCustodyError);
  });
});

describe.skipIf(process.platform !== "win32")("a Windows DPAPI-protected key file", () => {
  it("gives back the key for the same Windows user, and refuses an altered blob", () => {
    const key = randomBytes(32);
    const contents = wrapWithDpapi(key);
    const location = file("dpapi.key", contents);
    expect(inspectMasterKey(location)).toEqual({ protection: "dpapi" });
    expect(loadMasterKey(location).equals(key)).toBe(true);
    expect(contents).not.toContain(key.toString("base64"));

    const envelope = JSON.parse(contents);
    const blob = Buffer.from(envelope.blob, "base64");
    blob[blob.length - 1] ^= 0x01;
    expect(() => loadMasterKey(file("dpapi-altered.key", JSON.stringify({ ...envelope, blob: blob.toString("base64") })))).toThrow(KeyCustodyError);
  }, 60_000);
});

describe("the application's master key under custody", () => {
  it("keeps ciphertext written before wrapping readable after it", () => {
    const originalPath = process.env.MASTER_KEY_PATH;
    const key = randomBytes(32);
    const location = file("application.key", key.toString("base64"));
    try {
      process.env.MASTER_KEY_PATH = location;
      resetMasterKeyCache();
      const ciphertext = encrypt(Buffer.from("written under a plaintext key file"));

      writeMasterKeyFile(location, wrapWithPassphrase(key, PASSPHRASE, FAST));
      process.env[PASSPHRASE_VARIABLE] = PASSPHRASE;
      resetMasterKeyCache();
      expect(decrypt(ciphertext).toString()).toBe("written under a plaintext key file");
    } finally {
      process.env.MASTER_KEY_PATH = originalPath;
      delete process.env[PASSPHRASE_VARIABLE];
      resetMasterKeyCache();
    }
  });
});
