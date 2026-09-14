// PKI layer: signed, time-stamped checkpoints of the audit log's hash chain.
//
// A hash chain on its own is tamper-evident only against someone who edits rows without
// fixing up the hashes. Anyone who can write to the database can rewrite an entry and then
// recompute and rewrite every later hash, or delete entries from the end, and the chain still
// verifies. A checkpoint commits to the chain head, meaning the sequence number and the hash
// derived from the genesis hash, with a signature from a dedicated audit-signer certificate
// issued by the local CA, time-stamped by the local TSA. Verifying the log against its
// checkpoints detects a rewrite of any checkpointed entry and truncation below the latest
// checkpoint.
//
// Stated limits, also returned with every verification:
// - entries after the latest checkpoint are protected only by the hash chain;
// - deleting the newest checkpoints together with the entries they cover cannot be detected
//   from this database alone (Phase 7 anchors checkpoints outside it);
// - the signer's private key is encrypted with the same local master key as every other key,
//   so someone holding both the database and that key file can forge checkpoints.
import type { AuditCheckpoint, AuditSigner } from "@prisma/client";
import { randomBytes } from "node:crypto";
import * as x509 from "@peculiar/x509";
import { ConflictError, redactErrorForLog } from "@/lib/api";
import { walkAuditChain, type IntegrityResult } from "@/lib/audit/integrity";
import { GENESIS_HASH, appendAuditEntry } from "@/lib/audit/log";
import { requireCapability, type Actor } from "@/lib/auth/rbac";
import { sha256, sha256Hex } from "@/lib/crypto/hash";
import { configureCertificateProvider, spkiDerToPem, subjectPublicKey } from "@/lib/crypto/keys";
import { assertAlgorithm, isAlgorithm, orchestrator } from "@/lib/crypto/orchestrator";
import { pemBody } from "@/lib/crypto/pem";
import { decryptString, encryptString } from "@/lib/crypto/symmetric";
import { prisma } from "@/lib/db";
import { caCertificate, caSigningAlgorithm, caSigningKey, getRootCa } from "@/lib/pki/ca";
import { auditSignerAlgorithm } from "@/lib/pki/policy";
import { issueTimestampToken, verifyTimestampToken } from "@/lib/pki/tsa";

export const AUDIT_SIGNER_SUBJECT =
  "CN=OmniTrust Demo Audit Log Signer,O=OmniTrust Ledger,OU=Demo PKI - Not For Production Use";
export const CHECKPOINT_FORMAT = "omnitrust-audit-checkpoint/1";

const SIGNER_VALIDITY_MS = 5 * 365 * 86_400_000;

export const AUDIT_LOG_LIMITATIONS = [
  "Entries after the latest checkpoint are protected only by the hash chain.",
  "Deleting the newest checkpoints together with the entries they cover cannot be detected from this database alone.",
  "The checkpoint signer's key is encrypted with the same local master key as every other key, so someone with both the database and that key file can forge checkpoints.",
] as const;

function randomPositiveSerial(): string {
  const bytes = randomBytes(16);
  bytes[0] = (bytes[0] & 0x7f) | 0x01;
  return bytes.toString("hex").toUpperCase();
}

/** The active audit signer, created with its certificate on first use. */
export async function ensureAuditSigner(): Promise<AuditSigner> {
  const existing = await prisma.auditSigner.findFirst({
    where: { status: "ACTIVE" },
    orderBy: { createdAt: "desc" },
  });
  if (existing) return existing;

  configureCertificateProvider();
  const ca = await getRootCa();
  const root = caCertificate(ca);
  const algorithm = auditSignerAlgorithm();
  const keys = await orchestrator.generateKeyPair(algorithm);
  const notBefore = new Date();
  const notAfter = new Date(Math.min(notBefore.getTime() + SIGNER_VALIDITY_MS, root.notAfter.getTime()));
  const serialNumber = randomPositiveSerial();

  const certificate = await x509.X509CertificateGenerator.create({
    serialNumber,
    subject: AUDIT_SIGNER_SUBJECT,
    issuer: root.subject,
    notBefore,
    notAfter,
    signingKey: await caSigningKey(ca),
    publicKey: subjectPublicKey(keys.publicKeyPem),
    signingAlgorithm: caSigningAlgorithm(ca),
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.nonRepudiation, true),
    ],
  });

  const signer = await prisma.auditSigner.create({
    data: {
      issuerCaId: ca.id,
      name: AUDIT_SIGNER_SUBJECT,
      algorithm,
      serialNumber,
      certPem: certificate.toString("pem"),
      encryptedPrivateKey: encryptString(keys.privateKeyPem),
      expiresAt: notAfter,
      status: "ACTIVE",
    },
  });

  await appendAuditEntry({
    action: "AUDIT_SIGNER_CREATED",
    targetType: "AuditSigner",
    targetId: signer.id,
    metadata: { algorithm: signer.algorithm, serialNumber },
  });
  return signer;
}

export type CheckpointFields = Pick<AuditCheckpoint, "seq" | "entryHash" | "prevCheckpointHash" | "createdAt">;

/** The exact bytes a checkpoint signature covers. Line-based, so every field is unambiguous. */
export function checkpointPayload(fields: CheckpointFields): Buffer {
  return Buffer.from(
    [
      CHECKPOINT_FORMAT,
      `seq=${fields.seq}`,
      `entryHash=${fields.entryHash}`,
      `prevCheckpointHash=${fields.prevCheckpointHash}`,
      `createdAt=${fields.createdAt.toISOString()}`,
      "",
    ].join("\n"),
    "utf8",
  );
}

export function computeCheckpointHash(fields: CheckpointFields): string {
  return sha256Hex(checkpointPayload(fields));
}

export type CheckpointProblemCode =
  | "CHECKPOINT_ALTERED"
  | "CHECKPOINT_CHAIN_BROKEN"
  | "CHECKPOINT_SIGNATURE_INVALID"
  | "CHECKPOINT_TIMESTAMP_INVALID"
  | "LOG_TRUNCATED"
  | "LOG_REWRITTEN";

export type CheckpointProblem = {
  checkpointId: string;
  seq: number;
  problem: CheckpointProblemCode;
  detail: string;
};

export type CheckpointStatus = {
  id: string;
  seq: number;
  checkpointHash: string;
  createdAt: Date;
  /** The verified time-stamp's genTime, or null. */
  trustedTime: Date | null;
  timestamp: "VALID" | "INVALID" | "UNAVAILABLE" | "NONE";
  signer: string;
  valid: boolean;
};

export type AuditLogVerification = {
  valid: boolean;
  chain: IntegrityResult;
  head: { seq: number; hash: string } | null;
  checkpoints: CheckpointStatus[];
  problems: CheckpointProblem[];
  latestCheckpoint: CheckpointStatus | null;
  /** Entries protected by the hash chain alone. */
  entriesAfterLatestCheckpoint: number;
  explanation: string;
  limitations: readonly string[];
};

async function checkpointSignatureProblem(
  checkpoint: AuditCheckpoint & { signer: AuditSigner },
  root: x509.X509Certificate,
): Promise<string | null> {
  const { signer } = checkpoint;
  if (!isAlgorithm(signer.algorithm)) {
    return `the audit signer uses algorithm "${signer.algorithm}", which this installation does not support`;
  }

  configureCertificateProvider();
  const certificate = new x509.X509Certificate(new Uint8Array(pemBody(signer.certPem)));
  let chainValid = false;
  try {
    chainValid =
      certificate.issuer === root.subject &&
      (await certificate.verify({ publicKey: root.publicKey, signatureOnly: true }));
  } catch {
    chainValid = false;
  }
  if (!chainValid) return "the audit signer's certificate does not chain to the local CA";

  const publicKeyPem = spkiDerToPem(certificate.publicKey.rawData);
  let signatureValid = false;
  try {
    signatureValid =
      orchestrator.identifyPublicKey(publicKeyPem) === signer.algorithm &&
      (await orchestrator.verify({
        algorithm: signer.algorithm,
        message: checkpointPayload(checkpoint),
        signature: checkpoint.signature,
        publicKeyPem,
      }));
  } catch {
    signatureValid = false;
  }
  return signatureValid
    ? null
    : `the signature on the checkpoint at sequence ${checkpoint.seq} does not verify under the audit signer's key`;
}

/** Walks the chain, then checks every checkpoint and reconciles it with the log. */
export async function verifyAuditLog(): Promise<AuditLogVerification> {
  const walk = await walkAuditChain();
  const checkpoints = await prisma.auditCheckpoint.findMany({
    orderBy: { seq: "asc" },
    include: { signer: true },
  });
  const root = checkpoints.length > 0 ? caCertificate(await getRootCa()) : null;

  const problems: CheckpointProblem[] = [];
  const statuses: CheckpointStatus[] = [];
  let expectedPrevious = GENESIS_HASH;

  for (const checkpoint of checkpoints) {
    const found: CheckpointProblem[] = [];
    const flag = (problem: CheckpointProblemCode, detail: string) =>
      found.push({ checkpointId: checkpoint.id, seq: checkpoint.seq, problem, detail });

    const recomputed = computeCheckpointHash(checkpoint);
    if (recomputed !== checkpoint.checkpointHash) {
      flag(
        "CHECKPOINT_ALTERED",
        `the checkpoint at sequence ${checkpoint.seq} stores hash ${checkpoint.checkpointHash.slice(0, 16)}... but its fields hash to ${recomputed.slice(0, 16)}...`,
      );
    }
    if (checkpoint.prevCheckpointHash !== expectedPrevious) {
      flag(
        "CHECKPOINT_CHAIN_BROKEN",
        `the checkpoint at sequence ${checkpoint.seq} does not link to the checkpoint before it: a checkpoint was removed, reordered or altered`,
      );
    }
    expectedPrevious = recomputed;

    const signatureProblem = await checkpointSignatureProblem(checkpoint, root!);
    if (signatureProblem) flag("CHECKPOINT_SIGNATURE_INVALID", signatureProblem);

    let trustedTime: Date | null = null;
    let timestamp: CheckpointStatus["timestamp"] = "NONE";
    if (checkpoint.timestampToken) {
      const verification = await verifyTimestampToken(checkpoint.timestampToken, sha256(checkpoint.signature));
      timestamp = verification.status;
      if (verification.status === "VALID") trustedTime = verification.genTime;
      if (verification.status === "INVALID") {
        flag("CHECKPOINT_TIMESTAMP_INVALID", `the checkpoint at sequence ${checkpoint.seq}: ${verification.explanation}`);
      }
    }

    const derived = walk.derivedHashBySeq.get(checkpoint.seq);
    if (derived === undefined) {
      if (walk.lastSeq === null || checkpoint.seq > walk.lastSeq) {
        flag(
          "LOG_TRUNCATED",
          `a signed checkpoint covers entries up to sequence ${checkpoint.seq}, but the log ${
            walk.lastSeq === null ? "is empty" : `ends at sequence ${walk.lastSeq}`
          }: entries were deleted from the end`,
        );
      } else {
        flag("LOG_REWRITTEN", `the entry at sequence ${checkpoint.seq}, which a signed checkpoint covers, is missing`);
      }
    } else if (derived !== checkpoint.entryHash) {
      flag(
        "LOG_REWRITTEN",
        `entries up to sequence ${checkpoint.seq} no longer hash to the value signed at ${checkpoint.createdAt.toISOString()}: at least one was altered, even if the chain's hashes were recomputed`,
      );
    }

    problems.push(...found);
    statuses.push({
      id: checkpoint.id,
      seq: checkpoint.seq,
      checkpointHash: checkpoint.checkpointHash,
      createdAt: checkpoint.createdAt,
      trustedTime,
      timestamp,
      signer: checkpoint.signer.name,
      valid: found.length === 0,
    });
  }

  const valid = walk.result.valid && problems.length === 0;
  const latestCheckpoint = statuses.length > 0 ? statuses[statuses.length - 1] : null;
  const entriesAfterLatestCheckpoint =
    walk.lastSeq === null ? 0 : Math.max(0, walk.lastSeq - (latestCheckpoint?.seq ?? 0));
  const head = walk.lastSeq === null ? null : { seq: walk.lastSeq, hash: walk.derivedHashBySeq.get(walk.lastSeq)! };

  let explanation: string;
  if (!walk.result.valid) {
    explanation = `The hash chain is broken: ${walk.result.firstBreak!.detail}.`;
  } else if (problems.length > 0) {
    explanation = `The hash chain verifies on its own, but it disagrees with a signed checkpoint: ${problems[0].detail}.`;
  } else if (!latestCheckpoint) {
    explanation =
      `The hash chain is intact across ${walk.result.entriesChecked} entries. No signed checkpoint exists yet, so a ` +
      "consistent rewrite of the log, or deletion of its newest entries, would not be detectable.";
  } else {
    const time = latestCheckpoint.trustedTime ? `, time-stamped ${latestCheckpoint.trustedTime.toISOString()}` : "";
    explanation =
      `The hash chain is intact across ${walk.result.entriesChecked} entries and agrees with ${statuses.length} signed ` +
      `checkpoint${statuses.length === 1 ? "" : "s"}. The latest covers entries up to sequence ${latestCheckpoint.seq}${time}; ` +
      `${entriesAfterLatestCheckpoint} later entr${entriesAfterLatestCheckpoint === 1 ? "y is" : "ies are"} protected by the hash chain alone.`;
  }

  return {
    valid,
    chain: walk.result,
    head,
    checkpoints: statuses,
    problems,
    latestCheckpoint,
    entriesAfterLatestCheckpoint,
    explanation,
    limitations: AUDIT_LOG_LIMITATIONS,
  };
}

/** verifyAuditLog for a signed-in user, recorded in the log itself. */
export async function verifyAuditLogAs(actor: Actor): Promise<AuditLogVerification> {
  requireCapability(actor, "audit:verify");
  const result = await verifyAuditLog();
  await appendAuditEntry({
    actorUserId: actor.userId,
    action: "AUDIT_VERIFIED",
    targetType: "AuditLog",
    targetId: "audit-log",
    metadata: {
      valid: result.valid,
      entriesChecked: result.chain.entriesChecked,
      checkpointsChecked: result.checkpoints.length,
      firstProblem: result.chain.firstBreak?.problem ?? result.problems[0]?.problem ?? null,
    },
  });
  return result;
}

/**
 * Signs and time-stamps a commitment to the current chain head. Refuses when the log does not
 * verify, because a checkpoint over a tampered log would certify the tampering.
 */
export async function createAuditCheckpoint(actor: Actor): Promise<AuditCheckpoint> {
  requireCapability(actor, "audit:checkpoint");
  const signer = await ensureAuditSigner();

  const verification = await verifyAuditLog();
  if (!verification.valid) {
    throw new ConflictError(`Refusing to checkpoint an audit log that does not verify. ${verification.explanation}`);
  }
  const head = verification.head!;

  const previous = await prisma.auditCheckpoint.findFirst({ orderBy: { seq: "desc" } });
  if (previous && previous.seq >= head.seq) {
    throw new ConflictError(`Entries up to sequence ${previous.seq} are already checkpointed`);
  }

  const fields: CheckpointFields = {
    seq: head.seq,
    entryHash: head.hash,
    prevCheckpointHash: previous?.checkpointHash ?? GENESIS_HASH,
    createdAt: new Date(),
  };
  const payload = checkpointPayload(fields);
  const signature = await orchestrator.sign({
    algorithm: assertAlgorithm(signer.algorithm),
    message: payload,
    privateKeyPem: decryptString(signer.encryptedPrivateKey),
  });

  let token: Buffer | null = null;
  try {
    token = (await issueTimestampToken({ imprint: sha256(signature) })).token;
  } catch (error) {
    console.error("Time-stamping an audit checkpoint failed", redactErrorForLog(error));
  }

  let checkpoint: AuditCheckpoint;
  try {
    checkpoint = await prisma.auditCheckpoint.create({
      data: {
        ...fields,
        checkpointHash: sha256Hex(payload),
        signerId: signer.id,
        signature: new Uint8Array(signature),
        timestampToken: token ? new Uint8Array(token) : null,
        createdByUserId: actor.userId,
      },
    });
  } catch (error) {
    if ((error as { code?: unknown } | null)?.code === "P2002") {
      throw new ConflictError("Another checkpoint was created at the same moment; verify the log and try again");
    }
    throw error;
  }

  await appendAuditEntry({
    actorUserId: actor.userId,
    action: "AUDIT_CHECKPOINT_CREATED",
    targetType: "AuditCheckpoint",
    targetId: checkpoint.id,
    metadata: {
      seq: checkpoint.seq,
      checkpointHash: checkpoint.checkpointHash,
      signerSerial: signer.serialNumber,
      timestamped: token !== null,
    },
  });
  return checkpoint;
}

export type CheckpointSummary = {
  id: string;
  seq: number;
  entryHash: string;
  checkpointHash: string;
  createdAt: string;
  timestamped: boolean;
  signatureBytes: number;
  createdBy: string | null;
};

export async function listAuditCheckpoints(limit = 20): Promise<CheckpointSummary[]> {
  const checkpoints = await prisma.auditCheckpoint.findMany({
    orderBy: { seq: "desc" },
    take: limit,
    include: { createdBy: { select: { email: true } } },
  });
  return checkpoints.map((checkpoint) => ({
    id: checkpoint.id,
    seq: checkpoint.seq,
    entryHash: checkpoint.entryHash,
    checkpointHash: checkpoint.checkpointHash,
    createdAt: checkpoint.createdAt.toISOString(),
    timestamped: checkpoint.timestampToken !== null,
    signatureBytes: checkpoint.signature.length,
    createdBy: checkpoint.createdBy?.email ?? null,
  }));
}
