// The evidence pack's archive format. The CRC is checked against Node's own zlib.crc32, a
// different implementation of the same standard, and the archive is parsed back out of its
// central directory rather than trusted because it was just written.
import zlib from "node:zlib";
import { describe, expect, it } from "vitest";
import { crc32, createZip } from "@/lib/evidence/zip";

const LOCAL_HEADER = 0x04034b50;
const CENTRAL_HEADER = 0x02014b50;
const END_OF_CENTRAL_DIRECTORY = 0x06054b50;

/** Reads entries the way a reader must: from the central directory, by offset. */
function readEntries(archive: Buffer) {
  const endOffset = archive.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  expect(archive.readUInt32LE(endOffset)).toBe(END_OF_CENTRAL_DIRECTORY);

  const count = archive.readUInt16LE(endOffset + 10);
  let cursor = archive.readUInt32LE(endOffset + 16);
  const entries: { name: string; data: Buffer; storedCrc: number }[] = [];

  for (let index = 0; index < count; index += 1) {
    expect(archive.readUInt32LE(cursor)).toBe(CENTRAL_HEADER);
    const storedCrc = archive.readUInt32LE(cursor + 16);
    const size = archive.readUInt32LE(cursor + 24);
    const nameLength = archive.readUInt16LE(cursor + 28);
    const localOffset = archive.readUInt32LE(cursor + 42);
    const name = archive.subarray(cursor + 46, cursor + 46 + nameLength).toString("utf8");

    expect(archive.readUInt32LE(localOffset)).toBe(LOCAL_HEADER);
    const localNameLength = archive.readUInt16LE(localOffset + 26);
    const extraLength = archive.readUInt16LE(localOffset + 28);
    const start = localOffset + 30 + localNameLength + extraLength;

    entries.push({ name, data: archive.subarray(start, start + size), storedCrc });
    cursor += 46 + nameLength + archive.readUInt16LE(cursor + 30) + archive.readUInt16LE(cursor + 32);
  }

  return entries;
}

describe("crc32", () => {
  it("agrees with Node's own implementation", () => {
    const cases = [Buffer.alloc(0), Buffer.from("a"), Buffer.from("OmniTrust Ledger"), Buffer.from("x".repeat(10_000)), Buffer.from([0, 255, 128, 1, 254])];
    for (const input of cases) expect(crc32(input), input.subarray(0, 12).toString("hex")).toBe(zlib.crc32(input));
  });
});

describe("createZip", () => {
  const entries = [
    { name: "README.txt", data: Buffer.from("evidence pack\n") },
    { name: "document", data: Buffer.from([1, 2, 3, 0, 255, 254]) },
    { name: "verification.json", data: Buffer.from(JSON.stringify({ outcome: "VALID" })) },
  ];

  it("round-trips every entry, byte for byte, with a correct checksum", () => {
    const read = readEntries(createZip(entries));
    expect(read.map((entry) => entry.name)).toEqual(entries.map((entry) => entry.name));
    for (const [index, entry] of read.entries()) {
      expect(entry.data).toEqual(entries[index].data);
      expect(entry.storedCrc).toBe(zlib.crc32(entries[index].data));
    }
  });

  it("handles an empty archive and an empty member", () => {
    expect(readEntries(createZip([]))).toEqual([]);
    const read = readEntries(createZip([{ name: "empty", data: Buffer.alloc(0) }]));
    expect(read).toHaveLength(1);
    expect(read[0].data).toHaveLength(0);
    expect(read[0].storedCrc).toBe(zlib.crc32(Buffer.alloc(0)));
  });

  it("keeps non-ASCII names readable, which is why the UTF-8 flag is set", () => {
    const name = "signé-ملف.txt";
    const archive = createZip([{ name, data: Buffer.from("x") }]);
    expect(readEntries(archive)[0].name).toBe(name);
    // Bit 11 of the general purpose flag, in the local header.
    expect(archive.readUInt16LE(6) & 0x0800).toBe(0x0800);
  });

  it("is byte-identical for the same input and timestamp", () => {
    const when = new Date("2026-09-17T10:00:00Z");
    expect(createZip(entries, when)).toEqual(createZip(entries, when));
  });
});
