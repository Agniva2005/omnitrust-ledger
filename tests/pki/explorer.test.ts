// The certificate explorer reports what the certificate bytes, the signed CRL and the audit log
// say, so each field is checked against an independent reading of the same source.
import { createHash, X509Certificate } from "node:crypto";
import { beforeAll, describe, expect, it } from "vitest";
import type { Actor } from "@/lib/auth/rbac";
import { orchestrator } from "@/lib/crypto/orchestrator";
import { prisma } from "@/lib/db";
import { uploadDocument } from "@/lib/documents/service";
import { signDocument } from "@/lib/documents/signing";
import { ensureRootCa, getRootCa } from "@/lib/pki/ca";
import { issueCertificate, revokeCertificate } from "@/lib/pki/certificates";
import { issueCrl } from "@/lib/pki/crl";
import { exploreCertificate } from "@/lib/pki/explorer";
import { CA_ALGORITHM } from "@/lib/pki/policy";
import { seedUsers } from "@/prisma/fixtures";
import { resetDatabase } from "@/tests/helpers/db";
import { ensureMasterKey } from "@/tests/helpers/master-key";

let admin: Actor;
let signer: Actor;
let viewer: Actor;

beforeAll(async () => {
  ensureMasterKey();
  await resetDatabase();
  await seedUsers();
  await ensureRootCa();
  const users = await prisma.user.findMany();
  const actorFor = (email: string, role: Actor["role"]): Actor => ({ userId: users.find((user) => user.email === email)!.id, email, role });
  admin = actorFor("admin@demo", "ADMIN");
  signer = actorFor("signer@demo", "SIGNER");
  viewer = actorFor("viewer@demo", "VIEWER");
}, 60_000);

describe("certificate explorer", () => {
  it("reads fields, fingerprints and the chain from the certificate bytes", async () => {
    const certificate = await issueCertificate({ actor: signer, algorithm: CA_ALGORITHM });
    const explored = await exploreCertificate(viewer, certificate.id);
    const independent = new X509Certificate(certificate.certPem);

    expect(explored.fingerprintSha256).toBe(independent.fingerprint256);
    expect(explored.fingerprintSha256).toBe(createHash("sha256").update(independent.raw).digest("hex").toUpperCase().match(/.{2}/g)!.join(":"));
    expect(explored.serialNumber).toBe(independent.serialNumber.toUpperCase());
    expect(explored.notAfter).toBe(new Date(independent.validTo).toISOString());
    expect(explored.publicKey).toMatchObject({ algorithm: orchestrator.displayName(CA_ALGORITHM), matchesRecord: true });
    expect(explored.extensions.basicConstraints).toEqual({ ca: false, critical: true });
    expect(explored.extensions.keyUsage?.names).toEqual(expect.arrayContaining(["digitalSignature", "nonRepudiation"]));
    expect(explored.extensions.keyUsage?.names).not.toContain("keyCertSign");

    const ca = await getRootCa();
    expect(explored.chain[0].fingerprintSha256).toBe(new X509Certificate(ca.certPem).fingerprint256);
    expect(explored.chain[0].selfSigned).toBe(true);
    expect(explored.chain[1].issuer).toBe(explored.chain[0].subject);
    expect(explored.validation.valid).toBe(true);
    expect(explored.revocation.status).toBe("NOT_REVOKED");
    expect(explored.key).toMatchObject({ state: "ACTIVE", nextStates: ["ROTATED", "REVOKED"] });
  });

  it("follows the certificate and its key through revocation, from the CRL and the audit log", async () => {
    const certificate = await issueCertificate({ actor: signer, algorithm: CA_ALGORITHM });
    const document = await uploadDocument({ actor: signer, filename: "explorer.txt", mimeType: "text/plain", bytes: Buffer.from("explored") });
    await signDocument({ actor: signer, documentId: document.id, certificateId: certificate.id });
    await revokeCertificate({ actor: admin, certificateId: certificate.id, reason: "keyCompromise" });

    const explored = await exploreCertificate(viewer, certificate.id);

    expect(explored.status).toBe("REVOKED");
    expect(explored.key.state).toBe("REVOKED");
    expect(explored.revocation).toMatchObject({ status: "REVOKED", reason: "keyCompromise" });
    expect(explored.revocation.crlNumber).toBeGreaterThan(0);
    expect(explored.validation).toMatchObject({ valid: false, reason: "CERTIFICATE_REVOKED" });
    expect(explored.lifecycle.map((entry) => entry.action)).toEqual([
      "CERTIFICATE_ISSUED",
      "KEY_LIFECYCLE_CHANGED",
      "CERTIFICATE_REVOKED",
      "KEY_LIFECYCLE_CHANGED",
    ]);
    expect(explored.lifecycle[3].metadata).toMatchObject({ from: "ACTIVE", to: "REVOKED" });
    expect(explored.signatures.count).toBe(1);
    expect(explored.signatures.recent[0]).toMatchObject({ documentId: document.id, filename: "explorer.txt", timestamped: true });
  }, 30_000);

  it("reports revocation as unavailable, not as unrevoked, when the CRL cannot be authenticated", async () => {
    const certificate = await issueCertificate({ actor: signer, algorithm: CA_ALGORITHM });
    const list = await issueCrl();
    const forged = Buffer.from(list.der);
    forged[forged.length - 1] ^= 0x01;
    await prisma.revocationList.update({ where: { id: list.id }, data: { der: new Uint8Array(forged) } });
    try {
      expect((await exploreCertificate(viewer, certificate.id)).revocation.status).toBe("UNAVAILABLE");
    } finally {
      await prisma.revocationList.update({ where: { id: list.id }, data: { der: list.der } });
    }
  });
});
