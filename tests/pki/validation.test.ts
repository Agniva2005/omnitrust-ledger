import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import type { Actor } from "@/lib/auth/rbac";
import { prisma } from "@/lib/db";
import { ensureRootCa } from "@/lib/pki/ca";
import { issueCertificate, revokeCertificate } from "@/lib/pki/certificates";
import { markExpiredCertificates, validateCertificate } from "@/lib/pki/validation";
import { seedUsers } from "@/prisma/fixtures";
import { resetDatabase } from "@/tests/helpers/db";
import { ensureMasterKey } from "@/tests/helpers/master-key";

let admin: Actor;
let signer: Actor;

beforeAll(async () => {
  ensureMasterKey();
  await resetDatabase();
  await seedUsers();
  await ensureRootCa();

  const users = await prisma.user.findMany();
  admin = {
    userId: users.find((user) => user.email === "admin@demo")!.id,
    email: "admin@demo",
    role: "ADMIN",
  };
  signer = {
    userId: users.find((user) => user.email === "signer@demo")!.id,
    email: "signer@demo",
    role: "SIGNER",
  };
}, 60_000);

beforeEach(async () => {
  await prisma.certificate.deleteMany();
  await prisma.keyPair.deleteMany();
});

describe("validity period", () => {
  it("passes for a certificate inside its window", async () => {
    const certificate = await issueCertificate({ actor: signer, algorithm: "ED25519" });
    expect((await validateCertificate(certificate)).valid).toBe(true);
  });

  it("fails with CERTIFICATE_EXPIRED once the window has closed", async () => {
    const certificate = await issueCertificate({
      actor: signer,
      algorithm: "ED25519",
      notBefore: new Date("2024-01-01T00:00:00Z"),
      notAfter: new Date("2024-06-01T00:00:00Z"),
    });

    const validation = await validateCertificate(certificate);
    expect(validation.valid).toBe(false);
    expect(validation.reason).toBe("CERTIFICATE_EXPIRED");
    expect(validation.checks.find((check) => check.step === "Within validity period")?.passed).toBe(
      false,
    );
  });

  it("fails before the window opens", async () => {
    const notBefore = new Date(Date.now() + 86_400_000);
    const certificate = await issueCertificate({
      actor: signer,
      algorithm: "ECDSA_P256",
      notBefore,
      notAfter: new Date(notBefore.getTime() + 86_400_000),
    });
    expect((await validateCertificate(certificate)).reason).toBe("CERTIFICATE_EXPIRED");
  });

  it("evaluates against a caller-supplied instant, so expiry can be checked historically", async () => {
    const certificate = await issueCertificate({
      actor: signer,
      algorithm: "RSA",
      notBefore: new Date("2024-01-01T00:00:00Z"),
      notAfter: new Date("2024-06-01T00:00:00Z"),
    });

    expect((await validateCertificate(certificate, { at: new Date("2024-03-01") })).valid).toBe(true);
    expect((await validateCertificate(certificate, { at: new Date("2024-09-01") })).reason).toBe(
      "CERTIFICATE_EXPIRED",
    );
  });
});

describe("chain to the local CA", () => {
  it("fails with CERTIFICATE_CHAIN_INVALID when the CA signature does not hold", async () => {
    const certificate = await issueCertificate({ actor: signer, algorithm: "ED25519" });
    expect((await validateCertificate(certificate)).valid).toBe(true);

    // Flip a bit inside the signature, which is the final element of the DER. The
    // certificate still parses and still claims the right issuer; only the CA's
    // signature over it stops holding.
    const der = Buffer.from(
      certificate.certPem
        .split(/\r?\n/)
        .filter((line) => !line.startsWith("-----"))
        .join(""),
      "base64",
    );
    der[der.length - 5] ^= 0x01;
    const forgedPem = [
      "-----BEGIN CERTIFICATE-----",
      ...(der.toString("base64").match(/.{1,64}/g) ?? []),
      "-----END CERTIFICATE-----",
      "",
    ].join("\n");

    const impostor = await prisma.certificate.update({
      where: { id: certificate.id },
      data: { certPem: forgedPem },
    });

    const validation = await validateCertificate(impostor);
    expect(validation.valid).toBe(false);
    expect(validation.reason).toBe("CERTIFICATE_CHAIN_INVALID");
    expect(
      validation.checks.find(
        (check) => check.step === "Certificate signature verifies against the CA public key",
      )?.passed,
    ).toBe(false);
  });

  it("fails when the certificate PEM is corrupt", async () => {
    const certificate = await issueCertificate({ actor: signer, algorithm: "RSA" });
    const corrupted = await prisma.certificate.update({
      where: { id: certificate.id },
      data: { certPem: certificate.certPem.replace(/[A-Za-z]/, "!") },
    });

    const validation = await validateCertificate(corrupted);
    expect(validation.valid).toBe(false);
    expect(validation.reason).toBe("CERTIFICATE_CHAIN_INVALID");
  });

  it("fails when stored metadata disagrees with the certificate bytes", async () => {
    const certificate = await issueCertificate({ actor: signer, algorithm: "ED25519" });
    const tampered = await prisma.certificate.update({
      where: { id: certificate.id },
      data: { expiresAt: new Date("2099-01-01") },
    });

    const validation = await validateCertificate(tampered);
    expect(validation.reason).toBe("CERTIFICATE_CHAIN_INVALID");
    expect(
      validation.checks.find((check) => check.step === "Stored metadata matches the certificate")
        ?.passed,
    ).toBe(false);
  });
});

describe("reason precedence", () => {
  it("reports CERTIFICATE_EXPIRED for a certificate that is both expired and revoked", async () => {
    const certificate = await issueCertificate({
      actor: signer,
      algorithm: "ED25519",
      notBefore: new Date("2024-01-01T00:00:00Z"),
      notAfter: new Date("2024-06-01T00:00:00Z"),
    });
    await revokeCertificate({ actor: admin, certificateId: certificate.id });

    const reloaded = await prisma.certificate.findUniqueOrThrow({ where: { id: certificate.id } });
    const validation = await validateCertificate(reloaded);

    expect(validation.reason).toBe("CERTIFICATE_EXPIRED");
    // Both failures are still visible in the step list.
    expect(validation.checks.filter((check) => !check.passed)).toHaveLength(2);
  });
});

describe("markExpiredCertificates", () => {
  it("moves past-window certificates from ACTIVE to EXPIRED", async () => {
    const expiring = await issueCertificate({
      actor: signer,
      algorithm: "RSA",
      notBefore: new Date("2024-01-01T00:00:00Z"),
      notAfter: new Date("2024-06-01T00:00:00Z"),
    });
    const current = await issueCertificate({ actor: signer, algorithm: "ED25519" });

    expect(await markExpiredCertificates()).toBe(1);

    expect(
      (await prisma.certificate.findUniqueOrThrow({ where: { id: expiring.id } })).status,
    ).toBe("EXPIRED");
    expect(
      (await prisma.certificate.findUniqueOrThrow({ where: { id: current.id } })).status,
    ).toBe("ACTIVE");
  });

  it("is idempotent", async () => {
    await issueCertificate({
      actor: signer,
      algorithm: "RSA",
      notBefore: new Date("2024-01-01T00:00:00Z"),
      notAfter: new Date("2024-06-01T00:00:00Z"),
    });
    expect(await markExpiredCertificates()).toBe(1);
    expect(await markExpiredCertificates()).toBe(0);
  });
});
