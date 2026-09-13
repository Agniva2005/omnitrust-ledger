// Security Lab: attack scenarios, run against real services in a disposable sandbox.
//
// Nothing here simulates a result. Each scenario builds its own fixtures through the normal
// service layer, performs the attack the way someone with database or storage access would,
// and reports what the real verifier, integrity check or rate limiter then did. Every run
// starts with assertSandbox(), so these functions refuse to execute against anything but a
// throwaway database.
import fs from "node:fs/promises";
import { redactErrorForLog } from "@/lib/api";
import { verifyAuditChain } from "@/lib/audit/integrity";
import { GENESIS_HASH, computeEntryHash, serialiseMetadata } from "@/lib/audit/log";
import type { Actor } from "@/lib/auth/rbac";
import { loginRateLimit, accountKey } from "@/lib/auth/rate-limit";
import { authenticate } from "@/lib/auth/session";
import { ALGORITHMS, type Algorithm } from "@/lib/crypto/orchestrator";
import { encrypt } from "@/lib/crypto/symmetric";
import { prisma } from "@/lib/db";
import { uploadDocument } from "@/lib/documents/service";
import { signDocument } from "@/lib/documents/signing";
import { absolutePath } from "@/lib/documents/storage";
import { verifyDocument } from "@/lib/documents/verification";
import { createAuditCheckpoint, verifyAuditLog } from "@/lib/pki/audit-checkpoints";
import { ensureRootCa } from "@/lib/pki/ca";
import { issueCertificate, revokeCertificate } from "@/lib/pki/certificates";
import { verifyDetachedSignature } from "@/lib/pki/cms-signature";
import { issueCrl } from "@/lib/pki/crl";
import { CA_ALGORITHM } from "@/lib/pki/policy";
import { SCENARIOS, type ScenarioResult } from "@/lib/security-lab/catalog";
import { assertSandbox } from "@/lib/security-lab/guard";
import { DEMO_PASSWORD, seedUsers } from "@/prisma/fixtures";

type Actors = { admin: Actor; signer: Actor; verifier: Actor };

type Finding = { held: boolean; observed: string; steps: string[]; evidence: Record<string, unknown> };

async function actors(): Promise<Actors> {
  await seedUsers();
  await ensureRootCa();
  const users = await prisma.user.findMany();
  const actorFor = (email: string, role: Actor["role"]): Actor => ({
    userId: users.find((user) => user.email === email)!.id,
    email,
    role,
  });
  return {
    admin: actorFor("admin@demo", "ADMIN"),
    signer: actorFor("signer@demo", "SIGNER"),
    verifier: actorFor("verifier@demo", "VERIFIER"),
  };
}

/** A registered algorithm other than the given one, chosen from the registry. */
function otherAlgorithm(algorithm: Algorithm): Algorithm {
  const other = ALGORITHMS.find((candidate) => candidate !== algorithm);
  if (!other) throw new Error("This scenario needs at least two registered algorithms");
  return other;
}

async function signedDocument(
  { signer }: Actors,
  options: { text?: string; certificateId?: string } = {},
) {
  const certificateId =
    options.certificateId ?? (await issueCertificate({ actor: signer, algorithm: CA_ALGORITHM })).id;
  const content = Buffer.from(options.text ?? `Security Lab sandbox document ${Date.now()} ${Math.random()}`);
  const document = await uploadDocument({
    actor: signer,
    filename: `lab-${Math.random().toString(36).slice(2)}.txt`,
    mimeType: "text/plain",
    bytes: content,
  });
  await signDocument({ actor: signer, documentId: document.id, certificateId });
  const signature = await prisma.signature.findFirstOrThrow({
    where: { documentVersion: { documentId: document.id } },
    include: { documentVersion: true },
  });
  return { document, signature, content, certificateId };
}

async function verdict(actors: Actors, documentId: string) {
  const result = await verifyDocument(actors.verifier, documentId);
  return {
    result,
    summary: `${result.outcome}${result.reason ? ` / ${result.reason}` : ""}`,
    evidence: {
      outcome: result.outcome,
      reason: result.reason ?? null,
      failedSteps: result.steps.filter((step) => step.status !== "PASS" && !step.optional).map((step) => `${step.id}: ${step.status}`),
    },
  };
}

function expectVerdict(
  steps: string[],
  outcome: Awaited<ReturnType<typeof verdict>>,
  expectedOutcome: string,
  expectedReason: string | null,
): Finding {
  const held = outcome.result.outcome === expectedOutcome && (outcome.result.reason ?? null) === expectedReason;
  return { held, observed: `Verification returned ${outcome.summary}`, steps, evidence: outcome.evidence };
}

/** What someone with database write access does to defeat a plain hash chain. */
async function rewriteChainConsistently(seq: number) {
  const entries = await prisma.auditLogEntry.findMany({ orderBy: { seq: "asc" } });
  let prevHash = GENESIS_HASH;
  for (const entry of entries) {
    const fields = entry.seq === seq ? { ...entry, metadataJson: serialiseMetadata({ rewrittenBy: "security-lab" }) } : entry;
    const entryHash = computeEntryHash(prevHash, fields);
    await prisma.auditLogEntry.update({
      where: { id: entry.id },
      data: { metadataJson: fields.metadataJson, prevHash, entryHash },
    });
    prevHash = entryHash;
  }
}

const IMPLEMENTATIONS: Record<string, () => Promise<Finding>> = {
  async "control-untouched"() {
    const lab = await actors();
    const { document } = await signedDocument(lab);
    return expectVerdict(["Signed a fresh document", "Verified it without any change"], await verdict(lab, document.id), "VALID", null);
  },

  async "document-substitution"() {
    const lab = await actors();
    const { document, signature } = await signedDocument(lab, { text: "Pay the supplier 1,000.00" });
    await fs.writeFile(absolutePath(signature.documentVersion.storagePath), encrypt(Buffer.from("Pay the supplier 9,000.00")));
    return expectVerdict(
      ["Signed \"Pay the supplier 1,000.00\"", "Replaced the stored bytes with validly encrypted \"Pay the supplier 9,000.00\"", "Verified"],
      await verdict(lab, document.id),
      "INVALID",
      "HASH_MISMATCH",
    );
  },

  async "ciphertext-bitflip"() {
    const lab = await actors();
    const { document, signature } = await signedDocument(lab);
    const file = absolutePath(signature.documentVersion.storagePath);
    const stored = await fs.readFile(file);
    stored[stored.length - 1] ^= 0x01;
    await fs.writeFile(file, stored);
    return expectVerdict(["Signed a document", "Flipped the last bit of its ciphertext on disk", "Verified"], await verdict(lab, document.id), "INVALID", "HASH_MISMATCH");
  },

  async "signature-corruption"() {
    const lab = await actors();
    const { document, signature } = await signedDocument(lab);
    const corrupted = Buffer.from(signature.signatureBytes);
    corrupted[corrupted.length - 1] ^= 0x01;
    await prisma.signature.update({ where: { id: signature.id }, data: { signatureBytes: new Uint8Array(corrupted) } });
    return expectVerdict(["Signed a document", "Flipped a bit in the stored signature", "Verified"], await verdict(lab, document.id), "INVALID", "SIGNATURE_INVALID");
  },

  async "signature-replay"() {
    const lab = await actors();
    const first = await signedDocument(lab, { text: "Contract A" });
    const second = await signedDocument(lab, { text: "Contract B", certificateId: first.certificateId });
    await prisma.signature.update({
      where: { id: second.signature.id },
      data: { signatureBytes: first.signature.signatureBytes, timestampToken: first.signature.timestampToken },
    });
    return expectVerdict(
      ["Signed \"Contract A\" and \"Contract B\" with the same certificate", "Copied A's signature and time-stamp onto B", "Verified B"],
      await verdict(lab, second.document.id),
      "INVALID",
      "SIGNATURE_INVALID",
    );
  },

  async "algorithm-confusion"() {
    const lab = await actors();
    const { document, signature, certificateId } = await signedDocument(lab);
    const relabelled = otherAlgorithm(CA_ALGORITHM);
    await prisma.certificate.update({ where: { id: certificateId }, data: { algorithm: relabelled } });
    await prisma.signature.update({ where: { id: signature.id }, data: { algorithm: relabelled } });
    return expectVerdict(
      [`Signed under ${CA_ALGORITHM}`, `Relabelled the signature and certificate records as ${relabelled}`, "Verified"],
      await verdict(lab, document.id),
      "INVALID",
      "ALGORITHM_MISMATCH",
    );
  },

  async "key-substitution"() {
    const lab = await actors();
    const { document, signature } = await signedDocument(lab);
    const foreign = await issueCertificate({ actor: lab.signer, algorithm: otherAlgorithm(CA_ALGORITHM) });
    await prisma.signature.update({ where: { id: signature.id }, data: { certificateId: foreign.id } });
    return expectVerdict(
      ["Signed a document", `Pointed the signature at a ${foreign.algorithm} certificate`, "Verified"],
      await verdict(lab, document.id),
      "INVALID",
      "ALGORITHM_MISMATCH",
    );
  },

  async "compromised-key"() {
    const lab = await actors();
    const { document, certificateId } = await signedDocument(lab);
    await revokeCertificate({ actor: lab.admin, certificateId, reason: "keyCompromise", comment: "Security Lab" });
    return expectVerdict(
      ["Signed a document", "Revoked the certificate for keyCompromise with no invalidity date (a new CRL is issued)", "Verified"],
      await verdict(lab, document.id),
      "INVALID",
      "CERTIFICATE_REVOKED",
    );
  },

  async "timestamp-swap"() {
    const lab = await actors();
    const first = await signedDocument(lab);
    const second = await signedDocument(lab, { certificateId: first.certificateId });
    await prisma.signature.update({ where: { id: first.signature.id }, data: { timestampToken: second.signature.timestampToken } });
    return expectVerdict(
      ["Signed two documents", "Attached the second signature's genuine time-stamp token to the first", "Verified the first"],
      await verdict(lab, first.document.id),
      "INVALID",
      "TIMESTAMP_INVALID",
    );
  },

  async "forged-crl"() {
    const lab = await actors();
    const { document } = await signedDocument(lab);
    const list = await issueCrl();
    const forged = Buffer.from(list.der);
    forged[forged.length - 1] ^= 0x01;
    await prisma.revocationList.update({ where: { id: list.id }, data: { der: new Uint8Array(forged) } });
    return expectVerdict(
      ["Signed a document", "Altered the newest CA-signed revocation list in the database", "Verified"],
      await verdict(lab, document.id),
      "UNVERIFIABLE",
      "REVOCATION_STATUS_UNAVAILABLE",
    );
  },

  async "cms-content-tamper"() {
    const lab = await actors();
    const { signature, content } = await signedDocument(lab, { text: "Deliver 500 units" });
    const genuine = await verifyDetachedSignature(signature.cmsSignature!, content);
    const tampered = await verifyDetachedSignature(signature.cmsSignature!, Buffer.from("Deliver 900 units"));
    return {
      held: genuine.status === "VALID" && tampered.status === "INVALID",
      observed: `CMS verification: original ${genuine.status}, altered ${tampered.status}`,
      steps: ["Signed \"Deliver 500 units\" (a detached CMS signature is produced too)", "Verified the CMS signature against the original", "Verified it against \"Deliver 900 units\""],
      evidence: { original: genuine.status, altered: tampered.status, explanation: tampered.explanation },
    };
  },

  async "audit-row-edit"() {
    const lab = await actors();
    await signedDocument(lab);
    const target = await prisma.auditLogEntry.findFirstOrThrow({ where: { action: "DOCUMENT_UPLOADED" } });
    await prisma.auditLogEntry.update({ where: { id: target.id }, data: { metadataJson: serialiseMetadata({ filename: "something-else.txt" }) } });
    const result = await verifyAuditLog();
    return {
      held: !result.valid && result.chain.firstBreak?.seq === target.seq,
      observed: result.chain.firstBreak
        ? `Chain broken at sequence ${result.chain.firstBreak.seq} (${result.chain.firstBreak.problem})`
        : "The chain still verified",
      steps: ["Produced audit entries by signing a document", `Edited audit entry ${target.seq} directly in the database`, "Ran the integrity check"],
      evidence: { editedSeq: target.seq, firstBreak: result.chain.firstBreak ?? null },
    };
  },

  async "audit-consistent-rewrite"() {
    const lab = await actors();
    await signedDocument(lab);
    const checkpoint = await createAuditCheckpoint(lab.admin);
    const target = await prisma.auditLogEntry.findFirstOrThrow({ where: { action: "DOCUMENT_UPLOADED" } });
    await rewriteChainConsistently(target.seq);
    const chainOnly = await verifyAuditChain();
    const result = await verifyAuditLog();
    const problems = result.problems.map((problem) => problem.problem);
    return {
      held: chainOnly.valid && problems.includes("LOG_REWRITTEN"),
      observed: `Hash chain alone: ${chainOnly.valid ? "fooled (verifies)" : "broken"}; with checkpoints: ${problems.join(", ") || "no problem found"}`,
      steps: [
        "Produced audit entries and created a signed checkpoint",
        `Edited entry ${target.seq}, then recomputed and rewrote every later hash`,
        "Ran the chain check, then the checkpoint reconciliation",
      ],
      evidence: { checkpointSeq: checkpoint.seq, chainValid: chainOnly.valid, problems },
    };
  },

  async "audit-truncation"() {
    const lab = await actors();
    await signedDocument(lab);
    const checkpoint = await createAuditCheckpoint(lab.admin);
    const { count } = await prisma.auditLogEntry.deleteMany({ where: { seq: { gte: checkpoint.seq - 1 } } });
    const chainOnly = await verifyAuditChain();
    const result = await verifyAuditLog();
    const problems = result.problems.map((problem) => problem.problem);
    return {
      held: chainOnly.valid && problems.includes("LOG_TRUNCATED"),
      observed: `Hash chain alone: ${chainOnly.valid ? "fooled (verifies)" : "broken"}; with checkpoints: ${problems.join(", ") || "no problem found"}`,
      steps: ["Produced audit entries and created a signed checkpoint", `Deleted the newest ${count} entries`, "Ran the chain check, then the checkpoint reconciliation"],
      evidence: { checkpointSeq: checkpoint.seq, deleted: count, chainValid: chainOnly.valid, problems },
    };
  },

  async "login-brute-force"() {
    await actors();
    loginRateLimit.clear();
    const account = accountKey("signer@demo");
    const steps: string[] = [];
    let attempts = 0;
    // The same order the login route uses: check the limiter, then the password.
    while (loginRateLimit.retryAfterSeconds(account, null) === 0 && attempts < 20) {
      attempts += 1;
      if (!(await authenticate("signer@demo", `wrong-password-${attempts}`))) loginRateLimit.recordFailure(account, null);
    }
    steps.push(`Tried ${attempts} wrong passwords before the account was locked`);
    const retryAfter = loginRateLimit.retryAfterSeconds(account, null);
    const passwordWasCorrect = (await authenticate("signer@demo", DEMO_PASSWORD)) !== null;
    steps.push("Then tried the correct password", "The limiter is consulted first, as in the login route");
    loginRateLimit.clear();
    return {
      held: attempts === 5 && retryAfter > 0 && passwordWasCorrect,
      observed: `Locked after ${attempts} failures; the correct password is refused for ${retryAfter} s`,
      steps,
      evidence: { failuresBeforeLock: attempts, retryAfterSeconds: retryAfter, correctPasswordRefused: retryAfter > 0 },
    };
  },
};

export function hasImplementation(id: string): boolean {
  return Object.hasOwn(IMPLEMENTATIONS, id);
}

/** Runs one scenario. Refuses outright unless the process is pointed at a disposable sandbox. */
export async function runScenario(id: string): Promise<ScenarioResult> {
  assertSandbox();
  const definition = SCENARIOS.find((scenario) => scenario.id === id);
  if (!definition || !hasImplementation(id)) throw new Error(`Unknown Security Lab scenario: ${id}`);

  try {
    const finding = await IMPLEMENTATIONS[id]();
    return {
      id,
      title: definition.title,
      outcome: finding.held ? "HELD" : "FAILED",
      expected: definition.expected,
      observed: finding.observed,
      steps: finding.steps,
      evidence: finding.evidence,
    };
  } catch (error) {
    return {
      id,
      title: definition.title,
      outcome: "ERROR",
      expected: definition.expected,
      observed: `The scenario could not complete (${redactErrorForLog(error).summary})`,
      steps: [],
      evidence: {},
    };
  }
}
