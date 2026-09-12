import fs from "node:fs/promises";
import { beforeAll, describe, expect, it } from "vitest";
import { DecryptionIntegrityError } from "@/lib/crypto/symmetric";
import { sha256Hex } from "@/lib/crypto/hash";
import { absolutePath, readBlob, storedByteLength, writeBlob } from "@/lib/documents/storage";
import { ensureMasterKey } from "@/tests/helpers/master-key";

beforeAll(() => {
  ensureMasterKey();
});

describe("blob storage", () => {
  it("round-trips bytes through AES-256-GCM", async () => {
    const plaintext = Buffer.from("The quick brown fox jumps over the lazy dog");
    await writeBlob("documents/test/round-trip.bin", plaintext);
    expect(await readBlob("documents/test/round-trip.bin")).toEqual(plaintext);
  });

  it("does not store the plaintext on disk", async () => {
    const plaintext = Buffer.from("SENTINEL-PLAINTEXT-MARKER");
    await writeBlob("documents/test/encrypted.bin", plaintext);

    const onDisk = await fs.readFile(absolutePath("documents/test/encrypted.bin"));
    expect(onDisk.includes("SENTINEL-PLAINTEXT-MARKER")).toBe(false);
    // iv (12) + tag (16) of overhead.
    expect(onDisk.length).toBe(plaintext.length + 28);
  });

  it("uses a fresh IV per write, so identical plaintext yields different ciphertext", async () => {
    const plaintext = Buffer.from("same bytes");
    await writeBlob("documents/test/iv-a.bin", plaintext);
    await writeBlob("documents/test/iv-b.bin", plaintext);

    const a = await fs.readFile(absolutePath("documents/test/iv-a.bin"));
    const b = await fs.readFile(absolutePath("documents/test/iv-b.bin"));
    expect(a.equals(b)).toBe(false);
    expect(await readBlob("documents/test/iv-a.bin")).toEqual(
      await readBlob("documents/test/iv-b.bin"),
    );
  });

  it("detects a single flipped byte in the stored blob", async () => {
    const relative = "documents/test/tampered.bin";
    await writeBlob(relative, Buffer.from("original contents"));

    const target = absolutePath(relative);
    const stored = await fs.readFile(target);
    stored[stored.length - 1] ^= 0x01;
    await fs.writeFile(target, stored);

    await expect(readBlob(relative)).rejects.toThrow(DecryptionIntegrityError);
  });

  it("detects truncation", async () => {
    const relative = "documents/test/truncated.bin";
    await writeBlob(relative, Buffer.from("original contents"));

    const target = absolutePath(relative);
    const stored = await fs.readFile(target);
    await fs.writeFile(target, stored.subarray(0, stored.length - 4));

    await expect(readBlob(relative)).rejects.toThrow(DecryptionIntegrityError);
  });

  it("recomputes the same SHA-256 after a storage round-trip", async () => {
    const plaintext = Buffer.from("hash me, store me, read me back");
    await writeBlob("documents/test/hash-stable.bin", plaintext);
    expect(sha256Hex(await readBlob("documents/test/hash-stable.bin"))).toBe(sha256Hex(plaintext));
  });

  it("reports the stored (ciphertext) size", async () => {
    await writeBlob("documents/test/size.bin", Buffer.alloc(100, 7));
    expect(await storedByteLength("documents/test/size.bin")).toBe(128);
  });
});

describe("path containment", () => {
  it("refuses a storagePath that escapes the storage root", () => {
    expect(() => absolutePath("../../etc/passwd")).toThrow(/outside the storage root/);
  });
});
