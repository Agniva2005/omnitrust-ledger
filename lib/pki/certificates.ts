// PKI layer: certificate issuance and revocation.
import type { Certificate, KeyPair } from "@prisma/client";
import * as x509 from "@peculiar/x509";
import { BadRequestError, NotFoundError } from "@/lib/api";
import { appendAuditEntry } from "@/lib/audit/log";
import { AuthorizationError, requireCapability, type Actor } from "@/lib/auth/rbac";
import { configureCertificateProvider, spkiDerToPem, subjectPublicKey } from "@/lib/crypto/keys";
import { assertAlgorithm, orchestrator, type Algorithm } from "@/lib/crypto/orchestrator";
import { decryptString, encryptString } from "@/lib/crypto/symmetric";
import { prisma } from "@/lib/db";
import { caCertificate, caSigningAlgorithm, caSigningKey, getRootCa } from "@/lib/pki/ca";
import { issueCrl } from "@/lib/pki/crl";
import {
  assertCertificateState,
  assertCertificateTransition,
  assertKeyState,
  assertKeyTransition,
} from "@/lib/pki/keys";
import { assertRevocationReason, type RevocationReason } from "@/lib/pki/revocation";

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
  const metadata = orchestrator.describe(algorithm);
  if (!metadata.capabilities.x509Subject) {
    throw new BadRequestError(
      `${metadata.displayName} keys cannot be certified by this installation's CA`,
    );
  }

  const subjectUserId = input.subjectUserId ?? input.actor.userId;

  if (subjectUserId !== input.actor.userId && input.actor.role !== "ADMIN") {
    throw new AuthorizationError("Only an ADMIN can issue a certificate for another user");
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
  const caNotAfter = caCertificate(ca).notAfter;
  if (notAfter > caNotAfter) {
    throw new BadRequestError(
      `A certificate cannot outlive its issuing CA, which is valid until ${caNotAfter.toISOString()}`,
    );
  }

  const keys = await orchestrator.generateKeyPair(algorithm);
  // A provider that generates a key it does not itself recognise is misconfigured; never
  // certify a key under a label its own material contradicts.
  if (orchestrator.identifyPublicKey(keys.publicKeyPem) !== algorithm) {
    throw new Error(`Generated key does not identify as ${algorithm}`);
  }

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
    publicKey: subjectPublicKey(keys.publicKeyPem),
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
  /** RFC 5280 section 5.3.1 reason. Defaults to unspecified. */
  reason?: RevocationReason;
  /**
   * RFC 5280 section 5.3.2: when the key is known or suspected to have been compromised, or
   * the certificate otherwise became invalid. May precede the revocation itself.
   */
  invalidityDate?: Date;
  comment?: string;
};

/**
 * Section 6: only an ADMIN can revoke. Also revokes the underlying key pair, and has the CA
 * issue a new CRL so the revocation exists as signed evidence.
 */
export async function revokeCertificate({
  actor,
  certificateId,
  reason = "unspecified",
  invalidityDate,
  comment,
}: RevokeInput): Promise<Certificate> {
  requireCapability(actor, "certificate:revoke");
  assertRevocationReason(reason);

  const certificate = await prisma.certificate.findUnique({
    where: { id: certificateId },
    include: { keyPair: true },
  });
  if (!certificate) throw new NotFoundError("Certificate not found");

  const revokedAt = new Date();
  if (invalidityDate) {
    if (Number.isNaN(invalidityDate.getTime())) throw new BadRequestError("The invalidity date is not a valid date");
    if (invalidityDate > revokedAt) {
      throw new BadRequestError("The invalidity date cannot be later than the revocation itself");
    }
    if (invalidityDate < certificate.issuedAt) {
      throw new BadRequestError("The invalidity date cannot precede the certificate's validity period");
    }
  }

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
        revokedAt,
        revocationReason: reason,
        invalidityDate: invalidityDate ?? null,
        revocationComment: comment?.trim() || null,
      },
    }),
    prisma.keyPair.update({
      where: { id: certificate.keyPairId },
      data: { status: nextKeyState, revokedAt },
    }),
  ]);

  const crl = await issueCrl({ actorUserId: actor.userId });

  await appendAuditEntry({
    actorUserId: actor.userId,
    action: "CERTIFICATE_REVOKED",
    targetType: "Certificate",
    targetId: certificateId,
    metadata: {
      serialNumber: certificate.serialNumber,
      algorithm: certificate.algorithm,
      reason,
      invalidityDate: invalidityDate?.toISOString() ?? null,
      comment: updated.revocationComment,
      crlNumber: crl.crlNumber,
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
  // Sweep the Figure 6 ACTIVE -> EXPIRED transition here so the API and the page agree
  // on what they report. Validation never depends on this having run: it always reads
  // the certificate's own notBefore/notAfter.
  await markExpiredCertificates();
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

/**
 * Moves certificates whose window has closed from ACTIVE to EXPIRED (Figure 6).
 * Validation does not depend on this having run: it always re-reads the certificate's
 * own notBefore/notAfter.
 */
export async function markExpiredCertificates(at: Date = new Date()): Promise<number> {
  const stale = await prisma.certificate.findMany({
    where: { status: "ACTIVE", expiresAt: { lt: at } },
  });

  for (const certificate of stale) {
    await prisma.certificate.update({
      where: { id: certificate.id },
      data: {
        status: assertCertificateTransition(assertCertificateState(certificate.status), "EXPIRED"),
      },
    });
  }

  return stale.length;
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
