// Reusable demo fixtures, shared by prisma/seed.ts and the test suite.
//
// Everything here goes through the real service layer -- uploads are really hashed and
// stored, signatures are really produced by the orchestrator, and the audit log fills
// in as a side effect. Nothing is inserted pre-baked.
//
// The fixtures are driven by the provider registry: every registered algorithm gets a
// certificate and a signed sample document, so adding a provider changes the seeded data
// without this file changing.
import type { Certificate, KeyPair } from "@prisma/client";
import { prisma } from "../lib/db";
import { hashPassword } from "../lib/auth/session";
import type { Actor, Role } from "../lib/auth/rbac";
import { sha256Hex } from "../lib/crypto/hash";
import { ALGORITHMS, orchestrator, type Algorithm } from "../lib/crypto/orchestrator";
import { uploadDocument } from "../lib/documents/service";
import { signDocument } from "../lib/documents/signing";
import { writeBlob } from "../lib/documents/storage";
import { ensureRootCa } from "../lib/pki/ca";
import { issueCertificate } from "../lib/pki/certificates";
import { CA_ALGORITHM } from "../lib/pki/policy";

export const DEMO_PASSWORD = "demo1234";

export const DEMO_USERS: { email: string; role: Role }[] = [
  { email: "admin@demo", role: "ADMIN" },
  { email: "signer@demo", role: "SIGNER" },
  { email: "verifier@demo", role: "VERIFIER" },
  { email: "viewer@demo", role: "VIEWER" },
];

export async function seedUsers() {
  const passwordHash = await hashPassword(DEMO_PASSWORD);
  const users = [];
  for (const user of DEMO_USERS) {
    users.push(
      await prisma.user.upsert({
        where: { email: user.email },
        update: { role: user.role },
        create: { email: user.email, role: user.role, passwordHash },
      }),
    );
  }
  return users;
}

async function signerActor(): Promise<Actor> {
  const signer = await prisma.user.findUniqueOrThrow({ where: { email: "signer@demo" } });
  return { userId: signer.id, email: signer.email, role: "SIGNER" };
}

/** A filename-safe slug for an algorithm identifier, e.g. "ecdsa-p256". */
function algorithmSlug(algorithm: Algorithm): string {
  return algorithm.toLowerCase().replace(/_/g, "-");
}

/** One ACTIVE certificate per registered algorithm for signer@demo, plus one already expired. */
export async function seedCertificates(): Promise<Record<Algorithm, Certificate & { keyPair: KeyPair }>> {
  await ensureRootCa();
  const actor = await signerActor();

  const issued = {} as Record<Algorithm, Certificate & { keyPair: KeyPair }>;
  for (const algorithm of ALGORITHMS) {
    const existing = await prisma.certificate.findFirst({
      where: { subjectUserId: actor.userId, algorithm, status: "ACTIVE", expiresAt: { gt: new Date() } },
      include: { keyPair: true },
    });
    issued[algorithm] = existing ?? (await issueCertificate({ actor, algorithm }));
  }

  // An already-expired certificate, so the CERTIFICATE_EXPIRED path can be shown
  // without waiting or editing the database during a demo.
  const expired = await prisma.certificate.findFirst({
    where: { subjectUserId: actor.userId, status: { in: ["EXPIRED", "ACTIVE"] }, expiresAt: { lt: new Date() } },
  });
  if (!expired) {
    await issueCertificate({
      actor,
      algorithm: CA_ALGORITHM,
      notBefore: new Date("2024-01-01T00:00:00Z"),
      notAfter: new Date("2024-12-31T23:59:59Z"),
    });
  }

  return issued;
}

/** Sample contents, assigned to registered algorithms in order and reused cyclically. */
const SAMPLE_TEMPLATES = [
  {
    slug: "supply-agreement",
    text:
      "SUPPLY AGREEMENT\n\n" +
      "Acme Corporation agrees to supply 500 units per month to Demo Limited\n" +
      "at a unit price of 12.50, for a term of twelve months.\n",
  },
  {
    slug: "board-minutes",
    text:
      "BOARD MINUTES\n\n" +
      "The board approved the 2027 capital plan unanimously.\n" +
      "Present: four directors. Apologies: one.\n",
  },
  {
    slug: "audit-report",
    text:
      "INTERNAL AUDIT REPORT\n\n" +
      "No material weaknesses identified in the quarter under review.\n" +
      "Three low-severity observations are listed in the appendix.\n",
  },
  {
    slug: "service-contract",
    text:
      "SERVICE CONTRACT\n\n" +
      "Demo Limited engages Example Systems to operate the archive platform\n" +
      "for twenty-four months, with quarterly service reviews.\n",
  },
  {
    slug: "data-processing-addendum",
    text:
      "DATA PROCESSING ADDENDUM\n\n" +
      "The processor handles personal data only on documented instructions\n" +
      "and notifies the controller of any breach without undue delay.\n",
  },
];

const UNSIGNED_SAMPLE = {
  filename: "draft-policy.md",
  contents:
    "# Records Retention Policy (DRAFT)\n\n" +
    "Status: draft, not yet approved and not yet signed.\n" +
    "This document exists to show the 'not yet signed' state in the verification workflow.\n",
};

const TAMPERED_SAMPLE = {
  filename: "invoice-tampered.txt",
  original:
    "INVOICE 2026-0473\n\n" +
    "Consultancy services rendered in August 2026.\n" +
    "Amount due: 4,000.00\n" +
    "Payable within 30 days.\n",
  altered:
    "INVOICE 2026-0473\n\n" +
    "Consultancy services rendered in August 2026.\n" +
    "Amount due: 9,000.00\n" +
    "Payable within 30 days.\n",
};

export function signedSampleFor(algorithm: Algorithm, index: number) {
  const template = SAMPLE_TEMPLATES[index % SAMPLE_TEMPLATES.length];
  return {
    filename: `${template.slug}-${algorithmSlug(algorithm)}.txt`,
    contents: `${template.text}\nSigned under ${orchestrator.describe(algorithm).displayName}.\n`,
  };
}

export type SeededDocuments = Awaited<ReturnType<typeof seedDocuments>>;

/**
 * One unsigned sample, one signed sample per registered algorithm, and one pre-tampered
 * document for the canned "invalid" moment. The tampered one is signed normally and
 * *then* has its stored blob replaced with validly re-encrypted different content, so the
 * AES-GCM tag still passes and it is step 8's hash comparison that catches it.
 */
export async function seedDocuments() {
  const actor = await signerActor();
  const certificates = await seedCertificates();

  // A sample is found by the hash of its contents first -- the same way the upload
  // service recognises a duplicate -- and only then by filename. Matching by filename
  // alone made re-seeding fail on a database created by an earlier version of these
  // fixtures, where the same bytes had been stored under a different name.
  async function ensureDocument(filename: string, contents: string) {
    const byHash = await prisma.document.findFirst({
      where: { ownerUserId: actor.userId, currentHash: sha256Hex(Buffer.from(contents)) },
    });
    const found =
      byHash ?? (await prisma.document.findFirst({ where: { ownerUserId: actor.userId, filename } }));
    if (found) return found;
    return uploadDocument({
      actor,
      filename,
      mimeType: "text/plain",
      bytes: Buffer.from(contents),
    });
  }

  async function ensureSigned(documentId: string, certificateId: string) {
    const alreadySigned = await prisma.signature.findFirst({
      where: { documentVersion: { documentId } },
    });
    if (!alreadySigned) {
      await signDocument({ actor, documentId, certificateId });
    }
    return !alreadySigned;
  }

  const unsigned = await ensureDocument(UNSIGNED_SAMPLE.filename, UNSIGNED_SAMPLE.contents);

  const signed: Record<string, { id: string; filename: string }> = {};
  for (const [index, algorithm] of ALGORITHMS.entries()) {
    const sample = signedSampleFor(algorithm, index);
    const document = await ensureDocument(sample.filename, sample.contents);
    await ensureSigned(document.id, certificates[algorithm].id);
    signed[algorithm] = { id: document.id, filename: document.filename };
  }

  const tamperedAlgorithm = ALGORITHMS[ALGORITHMS.length - 1];
  const tampered = await ensureDocument(TAMPERED_SAMPLE.filename, TAMPERED_SAMPLE.original);
  if (await ensureSigned(tampered.id, certificates[tamperedAlgorithm].id)) {
    const version = await prisma.documentVersion.findFirstOrThrow({
      where: { documentId: tampered.id },
    });
    // The alteration happens at the storage layer, behind the application's back --
    // the recorded hash is deliberately left untouched.
    await writeBlob(version.storagePath, Buffer.from(TAMPERED_SAMPLE.altered));
  }

  return {
    unsigned: { id: unsigned.id, filename: unsigned.filename },
    signed,
    tampered: { id: tampered.id, filename: tampered.filename },
  };
}

export async function seedAll() {
  const users = await seedUsers();
  const certificates = await seedCertificates();
  const documents = await seedDocuments();
  return { users, certificates, documents };
}
