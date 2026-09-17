// A certificate's evidence pack: the certificate, what issued it, and what says whether it is
// still good — enough for someone else to reach their own conclusion about it.
//
// The document pack answers "is this file what was signed". This answers the other half: "is the
// certificate behind that signature one you would accept", which is a question about the chain
// and the revocation list rather than about any document.
import { appendAuditEntry } from "@/lib/audit/log";
import { requireCapability, type Actor } from "@/lib/auth/rbac";
import { sha256Hex } from "@/lib/crypto/hash";
import { createZip, type ZipEntry } from "@/lib/evidence/zip";
import { getRootCa } from "@/lib/pki/ca";
import { getCertificate } from "@/lib/pki/certificates";
import { crlPem, currentCrl } from "@/lib/pki/crl";
import { exploreCertificate } from "@/lib/pki/explorer";

function readme(parts: { serial: string; subject: string; status: string; detail: string; builtAt: string }): string {
  return `OmniTrust Ledger — certificate evidence pack
===========================================

Serial    ${parts.serial}
Subject   ${parts.subject}
Status    ${parts.status}
          ${parts.detail}
Built     ${parts.builtAt}

Contents
--------
  certificate.pem  the certificate itself
  ca.pem           the local root CA that issued it
  crl.pem          the CA-signed revocation list current when this pack was built
  explorer.json    every check this installation ran over the certificate, with its results
  README.txt       this description

Checking it yourself
--------------------
1. The certificate must chain to the CA:

     openssl verify -CAfile ca.pem certificate.pem

2. Its revocation status comes from the CRL, not from any database column:

     openssl crl -in crl.pem -noout -text

   Look for this certificate's serial in the revoked list. An entry carries a reason,
   and may carry an invalidity date — the time from which the key should no longer be
   trusted. A signature made before that date is not invalidated by the revocation.

3. Read the dates on the certificate itself:

     openssl x509 -in certificate.pem -noout -subject -issuer -dates -serial

This CA is self-signed and local. A successful chain check means these artefacts agree
with each other, not that anyone outside this installation trusts the issuer.
`;
}

export type CertificatePack = { filename: string; bytes: Buffer; serial: string; status: string };

export async function buildCertificatePack(actor: Actor, certificateId: string): Promise<CertificatePack> {
  requireCapability(actor, "certificate:read");

  const certificate = await getCertificate(actor, certificateId);
  const explored = await exploreCertificate(actor, certificateId);
  const ca = await getRootCa();
  const crl = await currentCrl();

  const builtAt = new Date();
  const entries: ZipEntry[] = [
    { name: "certificate.pem", data: Buffer.from(certificate.certPem, "utf8") },
    { name: "ca.pem", data: Buffer.from(ca.certPem, "utf8") },
    { name: "crl.pem", data: Buffer.from(crlPem(crl), "utf8") },
    { name: "explorer.json", data: Buffer.from(JSON.stringify(explored, null, 2), "utf8") },
    {
      name: "README.txt",
      data: Buffer.from(
        readme({
          serial: certificate.serialNumber,
          subject: explored.subject ?? certificate.subjectUserId,
          status: explored.revocation.status,
          detail: explored.revocation.detail,
          builtAt: builtAt.toISOString(),
        }),
        "utf8",
      ),
    },
  ];

  const bytes = createZip(entries, builtAt);

  await appendAuditEntry({
    actorUserId: actor.userId,
    action: "EVIDENCE_PACK_BUILT",
    targetType: "Certificate",
    targetId: certificate.id,
    metadata: { serialNumber: certificate.serialNumber, revocationStatus: explored.revocation.status, packSha256: sha256Hex(bytes) },
  });

  return {
    filename: `certificate-${certificate.serialNumber.slice(0, 12)}-evidence.zip`,
    bytes,
    serial: certificate.serialNumber,
    status: explored.revocation.status,
  };
}
