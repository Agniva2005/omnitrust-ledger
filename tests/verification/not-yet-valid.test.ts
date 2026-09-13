// A signature presented under a certificate whose validity began after the signature is proven
// to have existed. Found through an intermittent Security Lab result: verification refused it
// (correctly) but called it CERTIFICATE_EXPIRED. RFC 5280 treats "not yet valid" as a distinct
// condition, and the reason now says so. Built deterministically with an explicit notBefore an
// hour ahead, rather than relying on a second boundary.
import { beforeAll, describe, expect, it } from "vitest";
import type { Actor } from "@/lib/auth/rbac";
import { prisma } from "@/lib/db";
import { uploadDocument } from "@/lib/documents/service";
import { signDocument } from "@/lib/documents/signing";
import { outcomeForReason, verifyDocument } from "@/lib/documents/verification";
import { ensureRootCa } from "@/lib/pki/ca";
import { issueCertificate } from "@/lib/pki/certificates";
import { CA_ALGORITHM } from "@/lib/pki/policy";
import { validateCertificate } from "@/lib/pki/validation";
import { seedUsers } from "@/prisma/fixtures";
import { resetDatabase } from "@/tests/helpers/db";
import { ensureMasterKey } from "@/tests/helpers/master-key";

let signer: Actor;
let verifier: Actor;

beforeAll(async () => {
  ensureMasterKey();
  await resetDatabase();
  await seedUsers();
  await ensureRootCa();
  const users = await prisma.user.findMany();
  const actorFor = (email: string, role: Actor["role"]): Actor => ({ userId: users.find((user) => user.email === email)!.id, email, role });
  signer = actorFor("signer@demo", "SIGNER");
  verifier = actorFor("verifier@demo", "VERIFIER");
}, 60_000);

const inAnHour = () => new Date(Date.now() + 3_600_000);

describe("a certificate that is not yet valid", () => {
  it("is reported as CERTIFICATE_NOT_YET_VALID by validation, not as expired", async () => {
    const certificate = await issueCertificate({ actor: signer, algorithm: CA_ALGORITHM, notBefore: inAnHour(), notAfter: new Date(Date.now() + 86_400_000) });
    const validation = await validateCertificate(certificate);
    expect(validation).toMatchObject({ valid: false, reason: "CERTIFICATE_NOT_YET_VALID", window: "BEFORE" });
    expect(outcomeForReason("CERTIFICATE_NOT_YET_VALID")).toBe("INVALID");
  });

  it("makes a signature proven to predate the certificate INVALID with that reason", async () => {
    const genuine = await issueCertificate({ actor: signer, algorithm: CA_ALGORITHM });
    const future = await issueCertificate({ actor: signer, algorithm: CA_ALGORITHM, notBefore: inAnHour(), notAfter: new Date(Date.now() + 86_400_000) });
    const document = await uploadDocument({ actor: signer, filename: "predates.txt", mimeType: "text/plain", bytes: Buffer.from("signed before the named certificate existed") });
    await signDocument({ actor: signer, documentId: document.id, certificateId: genuine.id });
    await prisma.signature.updateMany({ where: { documentVersion: { documentId: document.id } }, data: { certificateId: future.id } });

    const result = await verifyDocument(verifier, document.id);

    expect(result.outcome).toBe("INVALID");
    expect(result.reason).toBe("CERTIFICATE_NOT_YET_VALID");
    expect(result.explanation).toMatch(/before the signing certificate's validity period began/);
    expect(result.steps.find((step) => step.id === "certificate-validity")?.status).toBe("FAIL");
    expect(result.trust.trustedTime).not.toBeNull();
  });

  it("still refuses to sign with a certificate that is not yet valid", async () => {
    const future = await issueCertificate({ actor: signer, algorithm: CA_ALGORITHM, notBefore: inAnHour(), notAfter: new Date(Date.now() + 86_400_000) });
    const document = await uploadDocument({ actor: signer, filename: "too-early.txt", mimeType: "text/plain", bytes: Buffer.from("too early") });
    await expect(signDocument({ actor: signer, documentId: document.id, certificateId: future.id })).rejects.toThrow(/CERTIFICATE_NOT_YET_VALID/);
  });
});
