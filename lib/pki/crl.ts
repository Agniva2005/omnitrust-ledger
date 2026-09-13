// PKI layer: certificate revocation lists (RFC 5280 section 5).
//
// Every revocation makes the CA issue a new, numbered, signed CRL. Verification reads
// revocation status from the newest CRL only after checking its signature against the CA
// and its freshness, so revocation evidence is a signed artefact rather than a database
// flag, and an unreadable, forged or stale list makes status unavailable rather than
// silently "not revoked". The same CRL is exported for independent checking with OpenSSL.
import type { RevocationList } from "@prisma/client";
import { AsnConvert } from "@peculiar/asn1-schema";
import { CRLNumber, id_ce_cRLNumber } from "@peculiar/asn1-x509";
import * as x509 from "@peculiar/x509";
import { appendAuditEntry } from "@/lib/audit/log";
import { configureCertificateProvider } from "@/lib/crypto/keys";
import { toPem } from "@/lib/crypto/pem";
import { prisma } from "@/lib/db";
import { caCertificate, caSigningAlgorithm, caSigningKey, getRootCa } from "@/lib/pki/ca";
import {
  REVOCATION_REASON_CODES,
  assertRevocationReason,
  reasonFromCode,
  type RevocationRecord,
} from "@/lib/pki/revocation";

export const CRL_VALIDITY_MS = 7 * 86_400_000;

/** CRL times are encoded to the second; storing them the same way keeps comparisons exact. */
function toWholeSecond(date: Date): Date {
  return new Date(Math.floor(date.getTime() / 1000) * 1000);
}

/** Serial numbers compare as integers: ignore case and leading zero bytes. */
export function normaliseSerial(serial: string): string {
  return serial.toUpperCase().replace(/^(00)+(?=.)/, "");
}

/**
 * X.509 serial numbers are positive INTEGERs (RFC 5280 section 4.1.2.2). X509CrlGenerator
 * encodes the hex it is given verbatim, so a serial whose first byte has its top bit set
 * became a negative INTEGER that no longer matched the certificate, and standard CRL
 * consumers such as OpenSSL treated the revoked certificate as unrevoked. A leading zero
 * byte keeps the INTEGER positive and byte-identical to the certificate's own encoding.
 */
export function positiveSerialHex(serial: string): string {
  const hex = serial.length % 2 === 0 ? serial : `0${serial}`;
  return Number.parseInt(hex.slice(0, 2), 16) >= 0x80 ? `00${hex}` : hex;
}

export class RevocationStatusUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RevocationStatusUnavailableError";
  }
}

type RevokedEntry = { serialNumber: string; revokedAt: Date; reason: string | null; invalidityDate: Date | null };

async function revokedEntries(caId: string): Promise<RevokedEntry[]> {
  const [certificates, authorities] = await Promise.all([
    prisma.certificate.findMany({ where: { issuerCaId: caId, status: "REVOKED" } }),
    prisma.timestampAuthority.findMany({ where: { issuerCaId: caId, status: "REVOKED" } }),
  ]);
  return [...certificates, ...authorities]
    .filter((row): row is typeof row & { revokedAt: Date } => row.revokedAt !== null)
    .map((row) => ({
      serialNumber: row.serialNumber,
      revokedAt: row.revokedAt,
      reason: row.revocationReason,
      invalidityDate: row.invalidityDate,
    }))
    .sort((a, b) => a.revokedAt.getTime() - b.revokedAt.getTime());
}

/** Issues and stores a new CRL covering every certificate this CA has revoked. */
export async function issueCrl(
  options: { at?: Date; actorUserId?: string | null } = {},
): Promise<RevocationList> {
  configureCertificateProvider();
  const ca = await getRootCa();
  const thisUpdate = toWholeSecond(options.at ?? new Date());
  const nextUpdate = new Date(thisUpdate.getTime() + CRL_VALIDITY_MS);

  const previous = await prisma.revocationList.findFirst({ orderBy: { crlNumber: "desc" } });
  const crlNumber = (previous?.crlNumber ?? 0) + 1;
  const entries = await revokedEntries(ca.id);

  const crl = await x509.X509CrlGenerator.create({
    issuer: caCertificate(ca).subject,
    thisUpdate,
    nextUpdate,
    entries: entries.map((entry) => {
      const reason = assertRevocationReason(entry.reason ?? "unspecified");
      return {
        serialNumber: positiveSerialHex(entry.serialNumber),
        revocationDate: toWholeSecond(entry.revokedAt),
        // RFC 5280 5.3.1: omit the reason extension rather than encode unspecified (0).
        reason: reason === "unspecified" ? undefined : REVOCATION_REASON_CODES[reason],
        invalidity: entry.invalidityDate ? toWholeSecond(entry.invalidityDate) : undefined,
      };
    }),
    extensions: [
      new x509.Extension(id_ce_cRLNumber, false, AsnConvert.serialize(new CRLNumber(crlNumber))),
    ],
    signingAlgorithm: caSigningAlgorithm(ca),
    signingKey: await caSigningKey(ca),
  });

  const stored = await prisma.revocationList.create({
    data: {
      issuerCaId: ca.id,
      crlNumber,
      thisUpdate,
      nextUpdate,
      der: new Uint8Array(crl.rawData),
    },
  });

  await appendAuditEntry({
    actorUserId: options.actorUserId ?? null,
    action: "CRL_ISSUED",
    targetType: "RevocationList",
    targetId: stored.id,
    metadata: {
      crlNumber,
      entries: entries.length,
      thisUpdate: thisUpdate.toISOString(),
      nextUpdate: nextUpdate.toISOString(),
    },
  });

  return stored;
}

/** The newest CRL, with a fresh one issued first if none exists or the newest has lapsed. */
export async function currentCrl(at: Date = new Date()): Promise<RevocationList> {
  const latest = await prisma.revocationList.findFirst({ orderBy: { crlNumber: "desc" } });
  if (latest && latest.nextUpdate > at) return latest;
  return issueCrl({ at });
}

export function crlPem(list: Pick<RevocationList, "der">): string {
  return toPem("X509 CRL", list.der);
}

export type AuthenticatedCrl = {
  crlNumber: number | null;
  thisUpdate: Date;
  nextUpdate: Date | null;
  entries: (RevocationRecord & { serialNumber: string })[];
};

/**
 * Parses a CRL and accepts it only if the local CA signed it and it is current at `at`.
 * Any failure means revocation status is unknown, never that nothing is revoked.
 */
export async function authenticateCrl(der: Uint8Array, at: Date = new Date()): Promise<AuthenticatedCrl> {
  configureCertificateProvider();
  const root = caCertificate(await getRootCa());

  let crl: x509.X509Crl;
  try {
    crl = new x509.X509Crl(new Uint8Array(der));
  } catch {
    throw new RevocationStatusUnavailableError("the certificate revocation list is malformed");
  }

  if (crl.issuer !== root.subject) {
    throw new RevocationStatusUnavailableError("the certificate revocation list was not issued by the local CA");
  }

  let signatureValid = false;
  try {
    signatureValid = await crl.verify({ publicKey: root.publicKey });
  } catch {
    signatureValid = false;
  }
  if (!signatureValid) {
    throw new RevocationStatusUnavailableError(
      "the certificate revocation list's signature does not verify under the CA key",
    );
  }

  if (crl.thisUpdate > at || (crl.nextUpdate && crl.nextUpdate <= at)) {
    throw new RevocationStatusUnavailableError("the certificate revocation list is not current");
  }

  const numberExtension = crl.getExtension(id_ce_cRLNumber);
  const crlNumber = numberExtension
    ? Number(AsnConvert.parse(numberExtension.value, CRLNumber).value)
    : null;

  const entries = crl.entries.map((entry) => {
    const reason = reasonFromCode(entry.reason);
    if (!reason) {
      throw new RevocationStatusUnavailableError(
        `the revocation list uses reason code ${entry.reason}, which this installation does not support`,
      );
    }
    return {
      serialNumber: normaliseSerial(entry.serialNumber),
      reason,
      revokedAt: entry.revocationDate,
      invalidityDate: entry.invalidity ?? null,
    };
  });

  return { crlNumber, thisUpdate: crl.thisUpdate, nextUpdate: crl.nextUpdate ?? null, entries };
}

export type RevocationStatus = {
  crlNumber: number | null;
  crlThisUpdate: Date;
  revocation: RevocationRecord | null;
};

/** Revocation status of one serial number, from the newest authenticated CRL. */
export async function revocationStatus(serialNumber: string, at: Date = new Date()): Promise<RevocationStatus> {
  const list = await currentCrl(at);
  const crl = await authenticateCrl(list.der, at);
  const entry = crl.entries.find((candidate) => candidate.serialNumber === normaliseSerial(serialNumber));
  return {
    crlNumber: crl.crlNumber,
    crlThisUpdate: crl.thisUpdate,
    revocation: entry
      ? { reason: entry.reason, revokedAt: entry.revokedAt, invalidityDate: entry.invalidityDate }
      : null,
  };
}
