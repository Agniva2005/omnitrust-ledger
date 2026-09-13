import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import {
  GENESIS_HASH,
  appendAuditEntry,
  canonicalEntry,
  computeEntryHash,
  serialiseMetadata,
} from "@/lib/audit/log";
import { verifyAuditChain } from "@/lib/audit/integrity";
import { sha256Hex } from "@/lib/crypto/hash";
import { prisma } from "@/lib/db";
import { seedUsers } from "@/prisma/fixtures";
import { resetDatabase } from "@/tests/helpers/db";
import { ensureMasterKey } from "@/tests/helpers/master-key";

beforeAll(() => {
  ensureMasterKey();
});

beforeEach(async () => {
  await resetDatabase();
});

async function appendSome(count: number) {
  const entries = [];
  for (let index = 0; index < count; index += 1) {
    entries.push(
      await appendAuditEntry({
        action: "DOCUMENT_UPLOADED",
        targetType: "Document",
        targetId: `doc-${index}`,
        metadata: { index },
      }),
    );
  }
  return entries;
}

describe("chain construction", () => {
  it("starts from the genesis hash and links each entry to the previous one", async () => {
    const entries = await appendSome(4);

    expect(entries[0].seq).toBe(1);
    expect(entries[0].prevHash).toBe(GENESIS_HASH);
    for (let index = 1; index < entries.length; index += 1) {
      expect(entries[index].seq).toBe(index + 1);
      expect(entries[index].prevHash).toBe(entries[index - 1].entryHash);
    }
  });

  it("computes entryHash as SHA256(prevHash + serialised entry), per Section 4", async () => {
    const [entry] = await appendSome(1);
    expect(entry.entryHash).toBe(sha256Hex(entry.prevHash + canonicalEntry(entry)));
    expect(entry.entryHash).toBe(computeEntryHash(entry.prevHash, entry));
    expect(entry.entryHash).toHaveLength(64);
  });

  it("serialises metadata deterministically regardless of key order", () => {
    expect(serialiseMetadata({ b: 2, a: 1 })).toBe(serialiseMetadata({ a: 1, b: 2 }));
  });

  it("cannot be fooled by field contents that contain the separator", () => {
    const base = {
      seq: 1,
      actorUserId: null,
      action: "DOCUMENT_UPLOADED",
      createdAt: new Date("2026-01-01T00:00:00Z"),
    };
    const first = canonicalEntry({ ...base, targetType: "a|b", targetId: "c", metadataJson: "{}" });
    const second = canonicalEntry({ ...base, targetType: "a", targetId: "b|c", metadataJson: "{}" });
    expect(first).not.toBe(second);
  });
});

describe("integrity check on an untouched log", () => {
  it("passes and reports how many entries it walked", async () => {
    await appendSome(6);
    const result = await verifyAuditChain();

    expect(result.valid).toBe(true);
    expect(result.entriesChecked).toBe(6);
    expect(result.breaks).toHaveLength(0);
    expect(result.firstBreak).toBeUndefined();
  });

  it("passes on an empty log", async () => {
    const result = await verifyAuditChain();
    expect(result.valid).toBe(true);
    expect(result.entriesChecked).toBe(0);
  });
});

describe("tamper detection (Phase 7 DoD)", () => {
  it("identifies exactly which entry was altered", async () => {
    const entries = await appendSome(6);
    const target = entries[2];

    // Edit a stored row directly, exactly as someone with database access would.
    await prisma.auditLogEntry.update({
      where: { id: target.id },
      data: { metadataJson: serialiseMetadata({ index: 999 }) },
    });

    const result = await verifyAuditChain();
    expect(result.valid).toBe(false);
    expect(result.firstBreak?.seq).toBe(target.seq);
    expect(result.firstBreak?.problem).toBe("ENTRY_HASH_MISMATCH");
    expect(result.firstBreak?.entryId).toBe(target.id);
    expect(result.firstBreak?.detail).toContain("was altered");
  });

  it("detects an altered action or target as readily as altered metadata", async () => {
    for (const data of [{ action: "USER_LOGIN" }, { targetId: "some-other-document" }]) {
      await resetDatabase();
      const entries = await appendSome(3);
      await prisma.auditLogEntry.update({ where: { id: entries[1].id }, data });

      const result = await verifyAuditChain();
      expect(result.valid).toBe(false);
      expect(result.firstBreak?.seq).toBe(2);
      expect(result.firstBreak?.problem).toBe("ENTRY_HASH_MISMATCH");
    }
  });

  it("detects an entry re-attributed to a different real user", async () => {
    // The interesting attribution tamper: blame someone else who actually exists, so
    // the foreign key still holds and only the hash chain gives it away.
    await resetDatabase();
    await seedUsers();
    const users = await prisma.user.findMany();

    const entry = await appendAuditEntry({
      actorUserId: users[0].id,
      action: "DOCUMENT_SIGNED",
      targetType: "Document",
      targetId: "doc-attribution",
      metadata: {},
    });
    await appendSome(2);

    await prisma.auditLogEntry.update({
      where: { id: entry.id },
      data: { actorUserId: users[1].id },
    });

    const result = await verifyAuditChain();
    expect(result.valid).toBe(false);
    expect(result.firstBreak?.seq).toBe(entry.seq);
    expect(result.firstBreak?.problem).toBe("ENTRY_HASH_MISMATCH");
  });

  it("detects a deleted entry as a sequence gap", async () => {
    const entries = await appendSome(5);
    await prisma.auditLogEntry.delete({ where: { id: entries[2].id } });

    const result = await verifyAuditChain();
    expect(result.valid).toBe(false);
    expect(result.firstBreak?.problem).toBe("SEQUENCE_GAP");
    expect(result.firstBreak?.seq).toBe(4);
  });

  it("detects an entry whose hash was recomputed but whose link was not", async () => {
    // A smarter tamper: fix up entryHash so the entry is self-consistent, but the
    // following entry's prevHash no longer matches.
    const entries = await appendSome(4);
    const target = entries[1];
    const altered = { ...target, metadataJson: serialiseMetadata({ index: 4242 }) };

    await prisma.auditLogEntry.update({
      where: { id: target.id },
      data: {
        metadataJson: altered.metadataJson,
        entryHash: computeEntryHash(target.prevHash, altered),
      },
    });

    const result = await verifyAuditChain();
    expect(result.valid).toBe(false);
    expect(result.firstBreak?.seq).toBe(3);
    expect(result.firstBreak?.problem).toBe("PREV_HASH_MISMATCH");
  });

  it("reports breaks downstream of the first one too", async () => {
    const entries = await appendSome(5);
    await prisma.auditLogEntry.update({
      where: { id: entries[0].id },
      data: { metadataJson: serialiseMetadata({ index: -1 }) },
    });

    const result = await verifyAuditChain();
    expect(result.breaks.length).toBeGreaterThanOrEqual(2);
    expect(result.firstBreak?.seq).toBe(1);
  });
});

describe("Section 6: concurrent appends", () => {
  it("does not corrupt the chain when many entries are appended at once", async () => {
    await Promise.all(
      Array.from({ length: 25 }, (_, index) =>
        appendAuditEntry({
          action: "DOCUMENT_VERIFIED",
          targetType: "Document",
          targetId: `concurrent-${index}`,
          metadata: { index },
        }),
      ),
    );

    const result = await verifyAuditChain();
    expect(result.valid).toBe(true);
    expect(result.entriesChecked).toBe(25);

    const sequences = (
      await prisma.auditLogEntry.findMany({ orderBy: { seq: "asc" } })
    ).map((entry) => entry.seq);
    expect(sequences).toEqual(Array.from({ length: 25 }, (_, index) => index + 1));
  });
});
