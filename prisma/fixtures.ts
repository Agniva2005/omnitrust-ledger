// Reusable demo fixtures, shared by prisma/seed.ts and the test suite.
//
// Everything here goes through the real service layer -- uploads are really hashed and
// stored, signatures are really produced by the orchestrator, and the audit log fills
// in as a side effect. Nothing is inserted pre-baked.
import type { Certificate, KeyPair } from "@prisma/client";
import { prisma } from "../lib/db";
import { hashPassword } from "../lib/auth/session";
import type { Actor, Role } from "../lib/auth/rbac";
import { ALGORITHMS, type Algorithm } from "../lib/crypto/types";
import { uploadDocument } from "../lib/documents/service";
import { signDocument } from "../lib/documents/signing";
import { writeBlob } from "../lib/documents/storage";
import { ensureRootCa } from "../lib/pki/ca";
import { issueCertificate } from "../lib/pki/certificates";

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

/** One ACTIVE certificate per algorithm for signer@demo, plus one already expired. */
export async function seedCertificates(): Promise<Record<Algorithm, Certificate & { keyPair: KeyPair }>> {
  await ensureRootCa();
  const actor = await signerActor();

  const issued = {} as Record<Algorithm, Certificate & { keyPair: KeyPair }>;
  for (const algorithm of ALGORITHMS) {
    const existing = await prisma.certificate.findFirst({
      where: { subjectUserId: actor.userId, algorithm, status: "ACTIVE" },
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
      algorithm: "ECDSA_P256",
      notBefore: new Date("2024-01-01T00:00:00Z"),
      notAfter: new Date("2024-12-31T23:59:59Z"),
    });
  }

  return issued;
}

const SAMPLE_DOCUMENTS = {
  unsigned: {
    filename: "draft-policy.md",
    contents:
      "# Records Retention Policy (DRAFT)\n\n" +
      "Status: draft, not yet approved and not yet signed.\n" +
      "This document exists to show the 'not yet signed' state in the verification workflow.\n",
  },
  rsa: {
    filename: "supply-agreement-rsa.txt",
    contents:
      "SUPPLY AGREEMENT\n\n" +
      "Acme Corporation agrees to supply 500 units per month to Demo Limited\n" +
      "at a unit price of 12.50, for a term of twelve months.\n\n" +
      "Signed under RSA-PSS 3072.\n",
  },
  ecdsa: {
    filename: "board-minutes-ecdsa.txt",
    contents:
      "BOARD MINUTES\n\n" +
      "The board approved the 2027 capital plan unanimously.\n" +
      "Present: four directors. Apologies: one.\n\n" +
      "Signed under ECDSA P-256.\n",
  },
  ed25519: {
    filename: "audit-report-ed25519.txt",
    contents:
      "INTERNAL AUDIT REPORT\n\n" +
      "No material weaknesses identified in the quarter under review.\n" +
      "Three low-severity observations are listed in the appendix.\n\n" +
      "Signed under EdDSA Ed25519.\n",
  },
  tampered: {
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
  },
};

export type SeededDocuments = Awaited<ReturnType<typeof seedDocuments>>;

/**
 * Four signed/unsigned samples plus one pre-tampered document for the canned "invalid"
 * moment. The tampered one is signed normally and *then* has its stored blob replaced
 * with validly re-encrypted different content, so the AES-GCM tag still passes and it is
 * step 8's hash comparison that catches it.
 */
export async function seedDocuments() {
  const actor = await signerActor();
  const certificates = await seedCertificates();

  const existing = await prisma.document.findMany({
    where: { filename: { in: Object.values(SAMPLE_DOCUMENTS).map((sample) => sample.filename) } },
  });
  const byFilename = new Map(existing.map((document) => [document.filename, document]));

  async function ensureDocument(filename: string, contents: string) {
    const found = byFilename.get(filename);
    if (found) return found;
    return uploadDocument({
      actor,
      filename,
      mimeType: "text/plain",
      bytes: Buffer.from(contents),
    });
  }

  const unsigned = await ensureDocument(
    SAMPLE_DOCUMENTS.unsigned.filename,
    SAMPLE_DOCUMENTS.unsigned.contents,
  );

  const signed: Record<string, { id: string; filename: string }> = {};
  for (const [key, algorithm] of [
    ["rsa", "RSA"],
    ["ecdsa", "ECDSA_P256"],
    ["ed25519", "ED25519"],
  ] as const) {
    const sample = SAMPLE_DOCUMENTS[key];
    const document = await ensureDocument(sample.filename, sample.contents);

    const alreadySigned = await prisma.signature.findFirst({
      where: { documentVersion: { documentId: document.id } },
    });
    if (!alreadySigned) {
      await signDocument({
        actor,
        documentId: document.id,
        certificateId: certificates[algorithm].id,
      });
    }
    signed[key] = { id: document.id, filename: document.filename };
  }

  const tamperedSample = SAMPLE_DOCUMENTS.tampered;
  const tampered = await ensureDocument(tamperedSample.filename, tamperedSample.original);
  const tamperedSigned = await prisma.signature.findFirst({
    where: { documentVersion: { documentId: tampered.id } },
  });
  if (!tamperedSigned) {
    await signDocument({
      actor,
      documentId: tampered.id,
      certificateId: certificates.ED25519.id,
    });

    const version = await prisma.documentVersion.findFirstOrThrow({
      where: { documentId: tampered.id },
    });
    // The alteration happens at the storage layer, behind the application's back --
    // the recorded hash is deliberately left untouched.
    await writeBlob(version.storagePath, Buffer.from(tamperedSample.altered));
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
