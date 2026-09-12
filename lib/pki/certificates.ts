// PKI layer: certificate issuance and revocation.
import type { Certificate, KeyPair } from "@prisma/client";
import * as x509 from "@peculiar/x509";
import { BadRequestError, ConflictError, NotFoundError } from "@/lib/api";
import { appendAuditEntry } from "@/lib/audit/log";
import { requireCapability, type Actor } from "@/lib/auth/rbac";
import {
  configureCertificateProvider,
  importPublicKey,
  spkiDerToPem,
} from "@/lib/crypto/keys";
import { orchestrator } from "@/lib/crypto/orchestrator";
import { decryptString, encryptString } from "@/lib/crypto/symmetric";
import { assertAlgorithm, type Algorithm } from "@/lib/crypto/types";
import { prisma } from "@/lib/db";
import { caCertificate, caSigningAlgorithm, caSigningKey, getRootCa } from "@/lib/pki/ca";
import {
  assertCertificateState,
  assertCertificateTransition,
  assertKeyState,
  assertKeyTransition,
} from "@/lib/pki/keys";

export const DEFAULT_VALIDITY_DAYS = 365;

export type IssueCertificateInput = {
  actor: Actor;
  algorithm: Algorithm;
  /** Defaults to the actor. Issuing for another user requires ADMIN. */
  subjectUserId?: string;
  validityDays?: number;
  /** Explicit window, used by the seed script and tests to create an expired certificate. */
  notBefore?: Date;
  notAfter?: Date;
};

function randomSerial(): string {
  // 16 random bytes, rendered as an even-length uppercase hex string like a real serial.
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  return Buffer.from(bytes).toString("hex").toUpperCase();
}

export async function issueCertificate(
  input: IssueCertificateInput,
): Promise<Certificate & { keyPair: KeyPair }> {
  requireCapability(input.actor, "certificate:issue");
  configureCertificateProvider();

  const algorithm = assertAlgorithm(input.algorithm);
  const subjectUserId = input.subjectUserId ?? input.actor.userId;

  if (subjectUserId !== input.actor.userId && input.actor.role !== "ADMIN") {
    throw new ConflictError("Only an ADMIN can issue a certificate for another user");
  }

  const subject = await prisma.user.findUnique({ where: { id: subjectUserId } });
  if (!subject) throw new NotFoundError("Subject user not found");

  const notBefore = input.notBefore ?? new Date();
  const notAfter =
    input.notAfter ??
    new Date(notBefore.getTime() + (input.validityDays ?? DEFAULT_VALIDITY_DAYS) * 86_400_000);
  if (notAfter <= notBefore) {
    throw new BadRequestError("Certificate validity window must end after it begins");
  }

  const ca = await getRootCa();
  const keys = await orchestrator.generateKeyPair(algorithm);

  const keyPair = await prisma.keyPair.create({
    data: {
      ownerUserId: subjectUserId,
      algorithm,
      publicKeyPem: keys.publicKeyPem,
      encryptedPrivateKey: encryptString(keys.privateKeyPem),
      status: assertKeyTransition("GENERATED", "ACTIVE"),
    },
  });

  const certificate = await x509.X509CertificateGenerator.create({
    serialNumber: randomSerial(),
    subject: `CN=${subject.email},O=OmniTrust Ledger,OU=Demo`,
    issuer: caCertificate(ca).subject,
    notBefore,
    notAfter,
    signingKey: await caSigningKey(ca),
    publicKey: await importPublicKey(algorithm, keys.publicKeyPem),
    signingAlgorithm: caSigningAlgorithm(ca),
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.nonRepudiation,
        true,
      ),
    ],
  });

  const record = await prisma.certificate.create({
    data: {
      keyPairId: keyPair.id,
      subjectUserId,
      issuerCaId: ca.id,
      serialNumber: certificate.serialNumber.toUpperCase(),
      algorithm,
      certPem: certificate.toString("pem"),
      issuedAt: notBefore,
      expiresAt: notAfter,
      status: assertCertificateTransition("REQUESTED", "ACTIVE"),
    },
    include: { keyPair: true },
  });

  await appendAuditEntry({
    actorUserId: input.actor.userId,
    action: "CERTIFICATE_ISSUED",
    targetType: "Certificate",
    targetId: record.id,
    metadata: {
      algorithm,
      serialNumber: record.serialNumber,
      subjectUserId,
      notBefore: notBefore.toISOString(),
      notAfter: notAfter.toISOString(),
      certificateByteLength: Buffer.from(record.certPem).length,
    },
  });

  await appendAuditEntry({
    actorUserId: input.actor.userId,
    action: "KEY_LIFECYCLE_CHANGED",
    targetType: "KeyPair",
    targetId: keyPair.id,
    metadata: { algorithm, from: "GENERATED", to: "ACTIVE" },
  });

  return record;
}

export type RevokeInput = {
  actor: Actor;
  certificateId: string;
  reason?: string;
};

/** Section 6: only an ADMIN can revoke. Also revokes the underlying key pair. */
export async function revokeCertificate({
  actor,
  certificateId,
  reason,
}: RevokeInput): Promise<Certificate> {
  requireCapability(actor, "certificate:revoke");

  const certificate = await prisma.certificate.findUnique({
    where: { id: certificateId },
    include: { keyPair: true },
  });
  if (!certificate) throw new NotFoundError("Certificate not found");

  const nextStatus = assertCertificateTransition(
    assertCertificateState(certificate.status),
    "REVOKED",
  );

  const keyState = assertKeyState(certificate.keyPair.status);
  const nextKeyState = keyState === "REVOKED" ? keyState : assertKeyTransition(keyState, "REVOKED");

  const [updated] = await prisma.$transaction([
    prisma.certificate.update({
      where: { id: certificateId },
      data: {
        status: nextStatus,
        revokedAt: new Date(),
        revocationReason: reason?.trim() || "Unspecified",
      },
    }),
    prisma.keyPair.update({
      where: { id: certificate.keyPairId },
      data: { status: nextKeyState, revokedAt: new Date() },
    }),
  ]);

  await appendAuditEntry({
    actorUserId: actor.userId,
    action: "CERTIFICATE_REVOKED",
    targetType: "Certificate",
    targetId: certificateId,
    metadata: {
      serialNumber: certificate.serialNumber,
      algorithm: certificate.algorithm,
      reason: updated.revocationReason,
    },
  });

  await appendAuditEntry({
    actorUserId: actor.userId,
    action: "KEY_LIFECYCLE_CHANGED",
    targetType: "KeyPair",
    targetId: certificate.keyPairId,
    metadata: { algorithm: certificate.algorithm, from: keyState, to: nextKeyState },
  });

  return updated;
}

export async function listCertificates(actor: Actor) {
  requireCapability(actor, "certificate:read");
  return prisma.certificate.findMany({
    orderBy: { issuedAt: "desc" },
    include: {
      subject: { select: { email: true } },
      keyPair: { select: { id: true, status: true, algorithm: true } },
    },
  });
}

export async function getCertificate(actor: Actor, certificateId: string) {
  requireCapability(actor, "certificate:read");
  const certificate = await prisma.certificate.findUnique({
    where: { id: certificateId },
    include: {
      subject: { select: { email: true } },
      keyPair: { select: { id: true, status: true, algorithm: true } },
    },
  });
  if (!certificate) throw new NotFoundError("Certificate not found");
  return certificate;
}

/** Certificates usable for signing right now, for the signing UI's picker. */
export async function signableCertificates(actor: Actor) {
  requireCapability(actor, "certificate:read");
  const now = new Date();
  return prisma.certificate.findMany({
    where: {
      subjectUserId: actor.userId,
      status: "ACTIVE",
      expiresAt: { gt: now },
      issuedAt: { lte: now },
    },
    orderBy: { issuedAt: "desc" },
    include: { keyPair: true },
  });
}

export function parseCertificate(certPem: string): x509.X509Certificate {
  configureCertificateProvider();
  return new x509.X509Certificate(certPem);
}

/**
 * Verification step 5: extract the public key from the certificate itself, not from
 * the KeyPair row, so verification depends on the certificate that was presented.
 */
export function publicKeyPemFromCertificate(certPem: string): string {
  return spkiDerToPem(parseCertificate(certPem).publicKey.rawData);
}

/** Decrypts a key pair's private key for a signing operation. */
export function privateKeyPemFor(keyPair: KeyPair): string {
  return decryptString(keyPair.encryptedPrivateKey);
}
