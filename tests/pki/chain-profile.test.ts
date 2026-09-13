// Certificate profile checks beyond "the CA signature holds": the issuer must be acting
// as a CA inside its own validity window, and a signing certificate must be an end
// entity whose key usage permits digital signatures. Each negative case is a real
// certificate signed by the real CA key, differing only in the property under test, and
// each is paired with a control proving the re-issuing helper itself does not break
// validity.
import * as x509 from "@peculiar/x509";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { BadRequestError } from "@/lib/api";
import type { Actor } from "@/lib/auth/rbac";
import { prisma } from "@/lib/db";
import { caCertificate, caSigningAlgorithm, caSigningKey, ensureRootCa, getRootCa } from "@/lib/pki/ca";
import { issueCertificate, parseCertificate } from "@/lib/pki/certificates";
import { validateCertificate, type CertificateValidation } from "@/lib/pki/validation";
import { seedUsers } from "@/prisma/fixtures";
import { resetDatabase } from "@/tests/helpers/db";
import { ensureMasterKey } from "@/tests/helpers/master-key";

let signer: Actor;

beforeAll(async () => {
  ensureMasterKey();
  await resetDatabase();
  await seedUsers();
  await ensureRootCa();
  const user = await prisma.user.findUniqueOrThrow({ where: { email: "signer@demo" } });
  signer = { userId: user.id, email: user.email, role: "SIGNER" };
}, 60_000);

beforeEach(async () => {
  await prisma.certificate.deleteMany();
  await prisma.keyPair.deleteMany();
});

function checkPassed(validation: CertificateValidation, step: string) {
  return validation.checks.find((check) => check.step === step)?.passed;
}

/** Issues a normal certificate, then replaces it with one signed by the same CA key but carrying `extensions`. */
async function reissueWithExtensions(extensions: x509.Extension[]) {
  const issued = await issueCertificate({ actor: signer, algorithm: "ECDSA_P256" });
  const ca = await getRootCa();
  const original = parseCertificate(issued.certPem);

  const reissued = await x509.X509CertificateGenerator.create({
    serialNumber: original.serialNumber,
    subject: original.subject,
    issuer: caCertificate(ca).subject,
    notBefore: original.notBefore,
    notAfter: original.notAfter,
    signingKey: await caSigningKey(ca),
    publicKey: original.publicKey,
    signingAlgorithm: caSigningAlgorithm(ca),
    extensions,
  });

  return prisma.certificate.update({
    where: { id: issued.id },
    data: { certPem: reissued.toString("pem") },
  });
}

describe("end-entity profile", () => {
  it("control: a re-issued certificate with the normal profile still validates", async () => {
    const certificate = await reissueWithExtensions([
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.nonRepudiation,
        true,
      ),
    ]);
    const validation = await validateCertificate(certificate);
    expect(validation.valid).toBe(true);
  });

  it("rejects a certificate whose key usage does not permit digital signatures", async () => {
    const certificate = await reissueWithExtensions([
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyEncipherment, true),
    ]);
    const validation = await validateCertificate(certificate);

    expect(validation.reason).toBe("CERTIFICATE_CHAIN_INVALID");
    expect(checkPassed(validation, "Key usage permits digital signatures")).toBe(false);
    // The CA signature itself is sound: only the profile is wrong.
    expect(checkPassed(validation, "Certificate signature verifies against the CA public key")).toBe(
      true,
    );
  });

  it("rejects a certificate with no keyUsage extension at all", async () => {
    const certificate = await reissueWithExtensions([
      new x509.BasicConstraintsExtension(false, undefined, true),
    ]);
    const validation = await validateCertificate(certificate);

    expect(validation.reason).toBe("CERTIFICATE_CHAIN_INVALID");
    expect(
      validation.checks.find((check) => check.step === "Key usage permits digital signatures")
        ?.detail,
    ).toMatch(/no keyUsage/);
  });

  it("rejects a CA certificate presented as a document-signing certificate", async () => {
    const certificate = await reissueWithExtensions([
      new x509.BasicConstraintsExtension(true, 0, true),
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyCertSign,
        true,
      ),
    ]);
    const validation = await validateCertificate(certificate);

    expect(validation.reason).toBe("CERTIFICATE_CHAIN_INVALID");
    expect(checkPassed(validation, "Certificate is an end-entity certificate (cA=FALSE)")).toBe(false);
  });
});

describe("issuer profile", () => {
  it("rejects a chain whose issuer certificate is not marked as a CA", async () => {
    const certificate = await issueCertificate({ actor: signer, algorithm: "ECDSA_P256" });
    const ca = await getRootCa();
    const root = caCertificate(ca);

    // Same name, same key, so the leaf's signature still verifies -- but no cA=TRUE.
    const notACa = await x509.X509CertificateGenerator.create({
      serialNumber: "02",
      subject: root.subject,
      issuer: root.subject,
      notBefore: root.notBefore,
      notAfter: root.notAfter,
      signingKey: await caSigningKey(ca),
      publicKey: root.publicKey,
      signingAlgorithm: caSigningAlgorithm(ca),
      extensions: [new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign, true)],
    });

    await prisma.certificateAuthority.update({
      where: { id: ca.id },
      data: { certPem: notACa.toString("pem") },
    });
    try {
      const validation = await validateCertificate(certificate);
      expect(validation.reason).toBe("CERTIFICATE_CHAIN_INVALID");
      expect(checkPassed(validation, "Issuer is a CA (basicConstraints cA=TRUE)")).toBe(false);
      expect(
        checkPassed(validation, "Certificate signature verifies against the CA public key"),
      ).toBe(true);
    } finally {
      await prisma.certificateAuthority.update({
        where: { id: ca.id },
        data: { certPem: ca.certPem },
      });
    }
  });

  it("evaluates the issuing CA's own validity window, not only the leaf's", async () => {
    const certificate = await issueCertificate({ actor: signer, algorithm: "ECDSA_P256" });
    const root = caCertificate(await getRootCa());

    const afterCaExpiry = new Date(root.notAfter.getTime() + 86_400_000);
    const validation = await validateCertificate(certificate, { at: afterCaExpiry });

    expect(validation.reason).toBe("CERTIFICATE_CHAIN_INVALID");
    expect(checkPassed(validation, "Issuer CA certificate within its validity period")).toBe(false);
  });

  it("refuses to issue a certificate that would outlive its issuing CA", async () => {
    const root = caCertificate(await getRootCa());
    await expect(
      issueCertificate({
        actor: signer,
        algorithm: "ECDSA_P256",
        notBefore: new Date(),
        notAfter: new Date(root.notAfter.getTime() + 86_400_000),
      }),
    ).rejects.toThrow(BadRequestError);
  });
});
