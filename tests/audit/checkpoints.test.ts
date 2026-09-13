// Signed audit checkpoints. The point of these tests is the gap they close: several tampering
// cases below pass the hash-chain check on its own and are caught only by reconciling the log
// with a signed checkpoint. The limits of that protection are tested too, as limits.
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { ConflictError } from "@/lib/api";
import { verifyAuditChain } from "@/lib/audit/integrity";
import { GENESIS_HASH, appendAuditEntry, computeEntryHash, serialiseMetadata } from "@/lib/audit/log";
import { AuthorizationError, type Actor } from "@/lib/auth/rbac";
import { orchestrator } from "@/lib/crypto/orchestrator";
import { prisma } from "@/lib/db";
import { ensureRootCa } from "@/lib/pki/ca";
import { publicKeyPemFromCertificate } from "@/lib/pki/certificates";
import {
  checkpointPayload,
  computeCheckpointHash,
  createAuditCheckpoint,
  ensureAuditSigner,
  verifyAuditLog,
  verifyAuditLogAs,
} from "@/lib/pki/audit-checkpoints";
import { issueTimestampToken } from "@/lib/pki/tsa";
import { seedUsers } from "@/prisma/fixtures";
import { resetDatabase } from "@/tests/helpers/db";
import { ensureMasterKey } from "@/tests/helpers/master-key";

const OPENSSL_AVAILABLE = spawnSync("openssl", ["version"]).status === 0;
const INTEROP_DIR = path.join(process.cwd(), "storage", "test", "openssl-audit");

let admin: Actor;
let verifier: Actor;
let viewer: Actor;

beforeAll(() => {
  ensureMasterKey();
});

beforeEach(async () => {
  await resetDatabase();
  await seedUsers();
  await ensureRootCa();
  const users = await prisma.user.findMany();
  const actorFor = (email: string, role: Actor["role"]): Actor => ({
    userId: users.find((user) => user.email === email)!.id,
    email,
    role,
  });
  admin = actorFor("admin@demo", "ADMIN");
  verifier = actorFor("verifier@demo", "VERIFIER");
  viewer = actorFor("viewer@demo", "VIEWER");
}, 60_000);

async function appendSome(count: number) {
  for (let index = 0; index < count; index += 1) {
    await appendAuditEntry({
      action: "DOCUMENT_UPLOADED",
      targetType: "Document",
      targetId: `doc-${index}-${Math.random()}`,
      metadata: { index },
    });
  }
}

/**
 * What an attacker with database write access does to defeat a plain hash chain: change an
 * entry, then recompute and rewrite every stored hash from there on so the chain verifies.
 */
async function rewriteConsistently(seq: number, metadata: Record<string, unknown>) {
  const entries = await prisma.auditLogEntry.findMany({ orderBy: { seq: "asc" } });
  let prevHash = GENESIS_HASH;
  for (const entry of entries) {
    const fields = entry.seq === seq ? { ...entry, metadataJson: serialiseMetadata(metadata) } : entry;
    const entryHash = computeEntryHash(prevHash, fields);
    await prisma.auditLogEntry.update({
      where: { id: entry.id },
      data: { metadataJson: fields.metadataJson, prevHash, entryHash },
    });
    prevHash = entryHash;
  }
}

const problemsOf = async () => (await verifyAuditLog()).problems.map((problem) => problem.problem);

describe("creating a checkpoint", () => {
  it("signs and time-stamps the verified chain head, and records itself in the log", async () => {
    await appendSome(4);
    const checkpoint = await createAuditCheckpoint(admin);

    const covered = await prisma.auditLogEntry.findUniqueOrThrow({ where: { seq: checkpoint.seq } });
    expect(checkpoint.entryHash).toBe(covered.entryHash);
    expect(checkpoint.prevCheckpointHash).toBe(GENESIS_HASH);
    expect(checkpoint.timestampToken).not.toBeNull();

    // Recorded after the checkpoint, so it is not covered by it. (Time-stamping the first
    // checkpoint also creates the Time-Stamp Authority, which is audited in between.)
    const recorded = await prisma.auditLogEntry.findFirstOrThrow({ where: { action: "AUDIT_CHECKPOINT_CREATED" } });
    expect(recorded.seq).toBeGreaterThan(checkpoint.seq);
    expect(JSON.parse(recorded.metadataJson)).toMatchObject({ seq: checkpoint.seq, checkpointHash: checkpoint.checkpointHash });

    const lastSeq = (await prisma.auditLogEntry.findFirstOrThrow({ orderBy: { seq: "desc" } })).seq;
    const result = await verifyAuditLog();
    expect(result.valid).toBe(true);
    expect(result.checkpoints).toHaveLength(1);
    expect(result.latestCheckpoint?.timestamp).toBe("VALID");
    expect(result.latestCheckpoint?.trustedTime).not.toBeNull();
    expect(result.entriesAfterLatestCheckpoint).toBe(lastSeq - checkpoint.seq);
    expect(result.entriesAfterLatestCheckpoint).toBeGreaterThanOrEqual(1);
    expect(result.explanation).toMatch(/agrees with 1 signed checkpoint/);
  }, 30_000);

  it("links each checkpoint to the one before it", async () => {
    await appendSome(2);
    const first = await createAuditCheckpoint(admin);
    await appendSome(2);
    const second = await createAuditCheckpoint(admin);

    expect(second.prevCheckpointHash).toBe(first.checkpointHash);
    expect((await verifyAuditLog()).valid).toBe(true);
  }, 30_000);

  it("is limited to admins", async () => {
    await appendSome(1);
    await expect(createAuditCheckpoint(verifier)).rejects.toThrow(AuthorizationError);
  });

  it("refuses to certify a log that does not verify", async () => {
    await appendSome(3);
    const entry = await prisma.auditLogEntry.findFirstOrThrow({ where: { action: "DOCUMENT_UPLOADED" } });
    await prisma.auditLogEntry.update({ where: { id: entry.id }, data: { metadataJson: serialiseMetadata({ index: 99 }) } });

    await expect(createAuditCheckpoint(admin)).rejects.toThrow(ConflictError);
    await expect(createAuditCheckpoint(admin)).rejects.toThrow(/does not verify/);
    expect(await prisma.auditCheckpoint.count()).toBe(0);
  });

  it("never forks: concurrent attempts leave one linear, verifying checkpoint chain", async () => {
    await appendSome(3);
    await ensureAuditSigner();
    const outcomes = await Promise.allSettled([createAuditCheckpoint(admin), createAuditCheckpoint(admin), createAuditCheckpoint(admin)]);

    expect(outcomes.some((outcome) => outcome.status === "fulfilled")).toBe(true);
    for (const outcome of outcomes) {
      if (outcome.status === "rejected") expect(outcome.reason).toBeInstanceOf(ConflictError);
    }
    expect((await verifyAuditLog()).valid).toBe(true);
  }, 30_000);
});

describe("tampering the hash chain alone cannot see", () => {
  it("detects a consistent rewrite of a checkpointed entry", async () => {
    await appendSome(4);
    const checkpoint = await createAuditCheckpoint(admin);
    await appendSome(2);

    const target = await prisma.auditLogEntry.findFirstOrThrow({ where: { action: "DOCUMENT_UPLOADED" } });
    await rewriteConsistently(target.seq, { index: "rewritten" });

    // The chain on its own is fooled...
    expect((await verifyAuditChain()).valid).toBe(true);
    // ...the checkpoint is not.
    const result = await verifyAuditLog();
    expect(result.valid).toBe(false);
    expect(result.problems).toEqual([
      expect.objectContaining({ problem: "LOG_REWRITTEN", seq: checkpoint.seq }),
    ]);
    expect(result.explanation).toMatch(/disagrees with a signed checkpoint/);
  }, 30_000);

  it("detects entries deleted from the end, below the latest checkpoint", async () => {
    await appendSome(4);
    const checkpoint = await createAuditCheckpoint(admin);
    await prisma.auditLogEntry.deleteMany({ where: { seq: { gte: checkpoint.seq - 1 } } });

    expect((await verifyAuditChain()).valid).toBe(true);
    const result = await verifyAuditLog();
    expect(result.valid).toBe(false);
    expect(result.problems.map((problem) => problem.problem)).toEqual(["LOG_TRUNCATED"]);
  }, 30_000);
});

describe("tampering with the checkpoints themselves", () => {
  it("detects a checkpoint whose committed hash was changed, even with its own hash recomputed", async () => {
    await appendSome(3);
    const checkpoint = await createAuditCheckpoint(admin);
    const forged = { ...checkpoint, entryHash: "f".repeat(64) };
    await prisma.auditCheckpoint.update({
      where: { id: checkpoint.id },
      data: { entryHash: forged.entryHash, checkpointHash: computeCheckpointHash(forged) },
    });

    // Without the signer's key the signature cannot be made to match.
    expect(await problemsOf()).toEqual(expect.arrayContaining(["CHECKPOINT_SIGNATURE_INVALID", "LOG_REWRITTEN"]));
  }, 30_000);

  it("detects an edited checkpoint row whose hash was left as it was", async () => {
    await appendSome(3);
    const checkpoint = await createAuditCheckpoint(admin);
    await prisma.auditCheckpoint.update({ where: { id: checkpoint.id }, data: { seq: checkpoint.seq - 1 } });
    expect(await problemsOf()).toEqual(expect.arrayContaining(["CHECKPOINT_ALTERED", "CHECKPOINT_SIGNATURE_INVALID"]));
  }, 30_000);

  it("detects a flipped bit in a checkpoint signature", async () => {
    await appendSome(2);
    const checkpoint = await createAuditCheckpoint(admin);
    const signature = Buffer.from(checkpoint.signature);
    signature[signature.length - 1] ^= 0x01;
    await prisma.auditCheckpoint.update({ where: { id: checkpoint.id }, data: { signature: new Uint8Array(signature) } });

    // The time-stamp was over the original signature, so it no longer matches either.
    expect(await problemsOf()).toEqual(expect.arrayContaining(["CHECKPOINT_SIGNATURE_INVALID", "CHECKPOINT_TIMESTAMP_INVALID"]));
  }, 30_000);

  it("detects a time-stamp swapped in from elsewhere", async () => {
    await appendSome(2);
    const checkpoint = await createAuditCheckpoint(admin);
    const unrelated = await issueTimestampToken({ imprint: Buffer.alloc(32, 7) });
    await prisma.auditCheckpoint.update({ where: { id: checkpoint.id }, data: { timestampToken: new Uint8Array(unrelated.token) } });

    expect(await problemsOf()).toEqual(["CHECKPOINT_TIMESTAMP_INVALID"]);
  }, 30_000);

  it("detects a checkpoint removed from the middle of the checkpoint chain", async () => {
    await appendSome(1);
    await createAuditCheckpoint(admin);
    const middle = await createAuditCheckpoint(admin);
    await createAuditCheckpoint(admin);
    await prisma.auditCheckpoint.delete({ where: { id: middle.id } });

    expect(await problemsOf()).toEqual(["CHECKPOINT_CHAIN_BROKEN"]);
  }, 30_000);
});

describe("stated limits, tested as limits", () => {
  it("cannot detect a consistent rewrite of entries after the latest checkpoint", async () => {
    await appendSome(2);
    const checkpoint = await createAuditCheckpoint(admin);
    await appendSome(2);
    const last = await prisma.auditLogEntry.findFirstOrThrow({ orderBy: { seq: "desc" } });
    await rewriteConsistently(last.seq, { index: "rewritten after the checkpoint" });

    const result = await verifyAuditLog();
    expect(result.valid).toBe(true);
    expect(result.entriesAfterLatestCheckpoint).toBe(last.seq - checkpoint.seq);
    expect(result.limitations[0]).toMatch(/after the latest checkpoint/);
  }, 30_000);

  it("cannot detect the newest checkpoint deleted together with the entries it covers", async () => {
    await appendSome(2);
    const first = await createAuditCheckpoint(admin);
    await appendSome(2);
    const second = await createAuditCheckpoint(admin);
    await prisma.auditCheckpoint.delete({ where: { id: second.id } });
    await prisma.auditLogEntry.deleteMany({ where: { seq: { gt: first.seq + 1 } } });

    expect((await verifyAuditLog()).valid).toBe(true);
  }, 30_000);

  it("reports the absence of checkpoints rather than implying protection", async () => {
    await appendSome(2);
    const result = await verifyAuditLog();
    expect(result.valid).toBe(true);
    expect(result.checkpoints).toHaveLength(0);
    expect(result.explanation).toMatch(/No signed checkpoint exists yet/);
  });
});

describe("independent verification", () => {
  it.runIf(OPENSSL_AVAILABLE)("verifies a checkpoint signature with the OpenSSL CLI", async () => {
    await appendSome(2);
    const checkpoint = await createAuditCheckpoint(admin);
    const signer = await prisma.auditSigner.findUniqueOrThrow({ where: { id: checkpoint.signerId } });
    const template = orchestrator.lookup(signer.algorithm)?.interoperability.opensslVerify;
    expect(template).toBeTruthy();

    fs.mkdirSync(INTEROP_DIR, { recursive: true });
    const file = (name: string) => path.join(INTEROP_DIR, name);
    fs.writeFileSync(file("payload.txt"), checkpointPayload(checkpoint));
    fs.writeFileSync(file("signature.bin"), Buffer.from(checkpoint.signature));
    fs.writeFileSync(file("public-key.pem"), publicKeyPemFromCertificate(signer.certPem));

    const argv = template!
      .replace("{publicKey}", file("public-key.pem"))
      .replace("{message}", file("payload.txt"))
      .replace("{signature}", file("signature.bin"))
      .split(" ")
      .slice(1);
    const result = spawnSync("openssl", argv, { encoding: "utf8" });
    expect(`${result.stdout}${result.stderr}`).toContain("Verified OK");

    fs.writeFileSync(file("payload.txt"), Buffer.concat([checkpointPayload(checkpoint), Buffer.from("x")]));
    expect(spawnSync("openssl", argv, { encoding: "utf8" }).status).not.toBe(0);
  }, 30_000);
});

describe("audit coverage added in this phase", () => {
  it("records creation of the CA, the Time-Stamp Authority and the audit signer", async () => {
    await issueTimestampToken({ imprint: Buffer.alloc(32, 1) });
    await ensureAuditSigner();
    const actions = (await prisma.auditLogEntry.findMany()).map((entry) => entry.action);
    expect(actions).toEqual(expect.arrayContaining(["CA_CREATED", "TSA_CREATED", "AUDIT_SIGNER_CREATED"]));
  });

  it("records who verified the log and what they found, and refuses a viewer", async () => {
    await appendSome(1);
    await verifyAuditLogAs(verifier);
    const entry = await prisma.auditLogEntry.findFirstOrThrow({ where: { action: "AUDIT_VERIFIED" } });
    expect(entry.actorUserId).toBe(verifier.userId);
    expect(JSON.parse(entry.metadataJson)).toMatchObject({ valid: true, checkpointsChecked: 0 });

    await expect(verifyAuditLogAs(viewer)).rejects.toThrow(AuthorizationError);
  });

  it("raises a non-conflict append failure at once instead of retrying it", async () => {
    await expect(
      appendAuditEntry({ actorUserId: "no-such-user", action: "USER_LOGIN", targetType: "User", targetId: "x" }),
    ).rejects.toMatchObject({ code: "P2003" });
    expect((await verifyAuditChain()).valid).toBe(true);
  });
});
