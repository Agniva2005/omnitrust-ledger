// The evidence pack: everything needed to re-check a signed document without this application.
//
// Nothing in here is generated for the pack. The document bytes, the signature, the
// certificates, the CRL and the time-stamp token are the stored artefacts; the verification
// result is a real run of the verifier at the moment the pack was built. The point is that the
// recipient does not have to trust this application — or run it — to check the claim.
import { NotFoundError } from "@/lib/api";
import { appendAuditEntry } from "@/lib/audit/log";
import { requireCapability, type Actor } from "@/lib/auth/rbac";
import { sha256Hex } from "@/lib/crypto/hash";
import { prisma } from "@/lib/db";
import { exportSignedDocument, safeFilename } from "@/lib/documents/export";
import { verifyDocument } from "@/lib/documents/verification";
import { createZip, type ZipEntry } from "@/lib/evidence/zip";
import { getRootCa } from "@/lib/pki/ca";
import { currentCrl } from "@/lib/pki/crl";

const PEM_WIDTH = 64;

function toPem(der: Uint8Array, label: string): string {
  const body = Buffer.from(der).toString("base64");
  const lines = body.match(new RegExp(`.{1,${PEM_WIDTH}}`, "g")) ?? [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}

function readme(parts: {
  filename: string;
  versionNumber: number;
  outcome: string;
  reason: string | null;
  algorithm: string;
  serial: string;
  signedHash: string;
  builtAt: string;
  files: { name: string; description: string }[];
}): string {
  const widest = Math.max(...parts.files.map((file) => file.name.length));
  const manifest = parts.files.map((file) => `  ${file.name.padEnd(widest)}  ${file.description}`).join("\n");

  return `OmniTrust Ledger — evidence pack
================================

Document      ${parts.filename} (version ${parts.versionNumber})
Signed hash   ${parts.signedHash}
Algorithm     ${parts.algorithm}
Certificate   ${parts.serial}
Verdict       ${parts.outcome}${parts.reason ? ` / ${parts.reason}` : ""}
Built         ${parts.builtAt}

The verdict above is what this installation's verifier returned when this pack was
built. Everything needed to reach that conclusion independently is in this folder.

Contents
--------
${manifest}

Checking it yourself
--------------------
1. The document's hash must equal the signed hash above:

     sha256sum document
     # or: certutil -hashfile document SHA256

2. The signature must verify under the certificate. For RSA-PSS and ECDSA P-256 the
   OpenSSL command line can do it directly:

     openssl cms -verify -binary -inform DER -in signature.p7s -content document \\
       -CAfile ca.pem -out /dev/null

   OpenSSL cannot process EdDSA Ed25519, ML-DSA-65 or the hybrid composite as CMS. For
   those, signature.bin holds the raw signature and certificate.pem the public key; check
   them with a library that implements the algorithm.

3. certificate.pem must chain to ca.pem, and must not appear in crl.pem. Note that this
   CA is self-signed and local: a successful check means the artefacts are consistent
   with each other, not that anyone outside this installation trusts the signer.

4. verification.json records every step this installation ran, including the ones a
   command-line check cannot reproduce, such as the trusted time-stamp.
`;
}

export type EvidencePack = { filename: string; bytes: Buffer; outcome: string; reason: string | null };

/**
 * Builds the pack for a document version, running a real verification as part of it.
 *
 * `actor` is null only for a share link, where possession of a valid, unexpired, unwithdrawn
 * token is the authorisation and the visitor has no account to attribute the pack to.
 */
export async function buildEvidencePack(actor: Actor | null, documentId: string, versionNumber?: number): Promise<EvidencePack> {
  if (actor) {
    requireCapability(actor, "document:read");
    requireCapability(actor, "document:verify");
  }

  const document = await prisma.document.findUnique({
    where: { id: documentId },
    include: { versions: { orderBy: { versionNumber: "desc" } } },
  });
  if (!document) throw new NotFoundError("Document not found");

  const version = versionNumber === undefined ? document.versions[0] : document.versions.find((candidate) => candidate.versionNumber === versionNumber);
  if (!version) throw new NotFoundError("Document version not found");

  const signature = await prisma.signature.findUnique({
    where: { documentVersionId: version.id },
    include: { certificate: true },
  });
  if (!signature) throw new NotFoundError("That version has no signature, so there is nothing to evidence");

  const visitor: Actor = actor ?? { userId: "", email: "", role: "VERIFIER" };
  const result = await verifyDocument(visitor, documentId, { versionNumber: version.versionNumber, viaShareToken: actor === null });
  const content = await exportSignedDocument(actor, documentId, "content", version.versionNumber);
  const certificate = await exportSignedDocument(actor, documentId, "certificate", version.versionNumber);
  const ca = await getRootCa();
  const crl = await currentCrl();

  const files: { name: string; description: string }[] = [];
  const entries: ZipEntry[] = [];
  const add = (name: string, data: Uint8Array, description: string) => {
    entries.push({ name, data });
    files.push({ name, description });
  };

  add(content.filename, content.bytes, "the document's exact bytes, as stored");
  add("certificate.pem", Buffer.from(certificate.bytes), "the signer's certificate");
  add("ca.pem", Buffer.from(ca.certPem, "utf8"), "the local root CA that issued it");
  add("crl.pem", Buffer.from(toPem(crl.der, "X509 CRL"), "utf8"), `the CA's signed revocation list, number ${crl.crlNumber}`);
  add("signature.bin", Buffer.from(signature.signatureBytes), `the raw signature, ${Buffer.from(signature.signatureBytes).length} bytes`);

  if (signature.cmsSignature) {
    add("signature.p7s", Buffer.from(signature.cmsSignature), "the same signature as a detached CMS structure (RFC 5652)");
  }
  if (signature.timestampToken) {
    add("timestamp.tsr", Buffer.from(signature.timestampToken), "the RFC 3161 token proving when the signature existed");
  }

  add(
    "verification.json",
    Buffer.from(JSON.stringify({ document: { id: document.id, filename: document.filename, versionNumber: version.versionNumber, signedHash: version.hash }, result }, null, 2), "utf8"),
    "every step of the verification, machine-readable",
  );

  const builtAt = new Date();
  add(
    "README.txt",
    Buffer.from(
      readme({
        filename: document.filename,
        versionNumber: version.versionNumber,
        outcome: result.outcome,
        reason: result.reason ?? null,
        algorithm: signature.algorithm,
        serial: signature.certificate.serialNumber,
        signedHash: version.hash,
        builtAt: builtAt.toISOString(),
        files,
      }),
      "utf8",
    ),
    "this description",
  );

  const bytes = createZip(entries, builtAt);

  await appendAuditEntry({
    actorUserId: actor?.userId ?? null,
    action: "EVIDENCE_PACK_BUILT",
    targetType: "Document",
    targetId: document.id,
    metadata: {
      versionNumber: version.versionNumber,
      outcome: result.outcome,
      reason: result.reason ?? null,
      files: entries.length,
      packSha256: sha256Hex(bytes),
    },
  });

  return {
    filename: `${safeFilename(document.filename)}-v${version.versionNumber}-evidence.zip`,
    bytes,
    outcome: result.outcome,
    reason: result.reason ?? null,
  };
}
