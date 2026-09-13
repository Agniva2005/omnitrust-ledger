import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { AuthorizationError, type Actor } from "@/lib/auth/rbac";
import { sha256 } from "@/lib/crypto/hash";
import { ALGORITHMS, orchestrator } from "@/lib/crypto/orchestrator";
import { prisma } from "@/lib/db";
import { CA_SUBJECT, ensureRootCa, getRootCa } from "@/lib/pki/ca";
import {
  issueCertificate,
  parseCertificate,
  privateKeyPemFor,
  publicKeyPemFromCertificate,
  revokeCertificate,
  signableCertificates,
} from "@/lib/pki/certificates";
import { CA_ALGORITHM } from "@/lib/pki/policy";
import { validateCertificate } from "@/lib/pki/validation";
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

  const users = await prisma.user.findMany();
  const find = (email: string) => users.find((user) => user.email === email)!;
  admin = { userId: find("admin@demo").id, email: "admin@demo", role: "ADMIN" };
  signer = { userId: find("signer@demo").id, email: "signer@demo", role: "SIGNER" };
  viewer = { userId: find("viewer@demo").id, email: "viewer@demo", role: "VIEWER" };
}, 60_000);

beforeEach(async () => {
  await prisma.certificate.deleteMany();
  await prisma.keyPair.deleteMany();
});

describe("local root CA", () => {
  it("creates exactly one CA, idempotently", async () => {
    const first = await ensureRootCa();
    const second = await ensureRootCa();
    expect(second.id).toBe(first.id);
    expect(await prisma.certificateAuthority.count()).toBe(1);
  });

  it("is self-signed, marked as a CA, and valid for ten years", async () => {
    const ca = await getRootCa();
    const certificate = parseCertificate(ca.certPem);

    expect(ca.algorithm).toBe(CA_ALGORITHM);
    // @peculiar/x509 renders a DN with a space after each comma; compare structurally.
    expect(certificate.subject.replace(/,\s+/g, ",")).toBe(CA_SUBJECT);
    expect(certificate.issuer).toBe(certificate.subject);
    expect(await certificate.verify({ publicKey: certificate.publicKey })).toBe(true);

    const years =
      (certificate.notAfter.getTime() - certificate.notBefore.getTime()) / (365.25 * 86_400_000);
    expect(years).toBeGreaterThan(9.9);
    expect(years).toBeLessThan(10.1);
  });

  it("says in its subject that it is not for production use", async () => {
    expect((await getRootCa()).name).toMatch(/Not For Production/i);
  });

  it("stores the CA private key encrypted, not in the clear", async () => {
    const ca = await getRootCa();
    expect(ca.encryptedPrivateKey).not.toContain("BEGIN");
    expect(ca.encryptedPrivateKey).not.toContain("PRIVATE KEY");
  });
});

describe.each(ALGORITHMS)("issuing a %s certificate", (algorithm) => {
  it("issues an ACTIVE certificate chaining to the local CA", async () => {
    const certificate = await issueCertificate({ actor: signer, algorithm });

    expect(certificate.algorithm).toBe(algorithm);
    expect(certificate.status).toBe("ACTIVE");
    expect(certificate.keyPair.status).toBe("ACTIVE");
    expect(certificate.keyPair.algorithm).toBe(algorithm);

    const validation = await validateCertificate(certificate);
    expect(validation.reason).toBeUndefined();
    expect(validation.valid).toBe(true);
  });

  it("carries a public key that matches the generated key pair", async () => {
    const certificate = await issueCertificate({ actor: signer, algorithm });
    const fromCertificate = publicKeyPemFromCertificate(certificate.certPem);
    expect(fromCertificate.replace(/\s/g, "")).toBe(
      certificate.keyPair.publicKeyPem.replace(/\s/g, ""),
    );
  });

  it("certifies a key whose own material identifies as the recorded algorithm", async () => {
    const certificate = await issueCertificate({ actor: signer, algorithm });
    expect(orchestrator.identifyPublicKey(publicKeyPemFromCertificate(certificate.certPem))).toBe(
      algorithm,
    );
  });

  it("produces a working key pair: the certificate's public key verifies its own signature", async () => {
    const certificate = await issueCertificate({ actor: signer, algorithm });
    const message = sha256("a document to sign");

    const signature = await orchestrator.sign({
      algorithm,
      message,
      privateKeyPem: privateKeyPemFor(certificate.keyPair),
    });

    expect(
      await orchestrator.verify({
        algorithm,
        message,
        signature,
        publicKeyPem: publicKeyPemFromCertificate(certificate.certPem),
      }),
    ).toBe(true);
  });

  it("stores the private key encrypted", async () => {
    const certificate = await issueCertificate({ actor: signer, algorithm });
    expect(certificate.keyPair.encryptedPrivateKey).not.toContain("PRIVATE KEY");
    expect(privateKeyPemFor(certificate.keyPair)).toContain("BEGIN PRIVATE KEY");
  });

  it("names the subject and restricts key usage to signing", async () => {
    const certificate = await issueCertificate({ actor: signer, algorithm });
    const parsed = parseCertificate(certificate.certPem);
    expect(parsed.subject).toContain("CN=signer@demo");
    expect(parsed.getExtension("2.5.29.15")).toBeTruthy(); // keyUsage
    expect(parsed.getExtension("2.5.29.19")).toBeTruthy(); // basicConstraints
  });

  it("issues a unique serial number each time", async () => {
    const first = await issueCertificate({ actor: signer, algorithm });
    const second = await issueCertificate({ actor: signer, algorithm });
    expect(first.serialNumber).not.toBe(second.serialNumber);
    expect(first.serialNumber).toMatch(/^[0-9A-F]+$/);
  });
});

describe("revocation", () => {
  it("marks the certificate and its key pair revoked, with a reason", async () => {
    const certificate = await issueCertificate({ actor: signer, algorithm: "ECDSA_P256" });
    const revoked = await revokeCertificate({
      actor: admin,
      certificateId: certificate.id,
      reason: "keyCompromise",
      comment: "Key compromise (demo)",
    });

    expect(revoked.status).toBe("REVOKED");
    expect(revoked.revokedAt).toBeInstanceOf(Date);
    expect(revoked.revocationReason).toBe("keyCompromise");
    expect(revoked.revocationComment).toBe("Key compromise (demo)");

    const keyPair = await prisma.keyPair.findUniqueOrThrow({ where: { id: certificate.keyPairId } });
    expect(keyPair.status).toBe("REVOKED");
  });

  it("makes validation fail with CERTIFICATE_REVOKED", async () => {
    const certificate = await issueCertificate({ actor: signer, algorithm: "RSA" });
    expect((await validateCertificate(certificate)).valid).toBe(true);

    await revokeCertificate({ actor: admin, certificateId: certificate.id });

    const reloaded = await prisma.certificate.findUniqueOrThrow({ where: { id: certificate.id } });
    const validation = await validateCertificate(reloaded);
    expect(validation.valid).toBe(false);
    expect(validation.reason).toBe("CERTIFICATE_REVOKED");
    expect(validation.checks.find((check) => check.step === "Not revoked")?.passed).toBe(false);
  });

  it("leaves other certificates valid (Phase 4 DoD)", async () => {
    const revokedCert = await issueCertificate({ actor: signer, algorithm: "RSA" });
    const activeCerts = [
      await issueCertificate({ actor: signer, algorithm: "ECDSA_P256" }),
      await issueCertificate({ actor: signer, algorithm: "ED25519" }),
    ];

    await revokeCertificate({ actor: admin, certificateId: revokedCert.id });

    const reloaded = await prisma.certificate.findUniqueOrThrow({ where: { id: revokedCert.id } });
    expect((await validateCertificate(reloaded)).reason).toBe("CERTIFICATE_REVOKED");
    for (const certificate of activeCerts) {
      expect((await validateCertificate(certificate)).valid).toBe(true);
    }
  });

  it("Section 6: only an ADMIN can revoke", async () => {
    const certificate = await issueCertificate({ actor: signer, algorithm: "ED25519" });
    for (const actor of [signer, viewer]) {
      await expect(
        revokeCertificate({ actor, certificateId: certificate.id }),
      ).rejects.toThrow(AuthorizationError);
    }
    await expect(
      revokeCertificate({ actor: admin, certificateId: certificate.id }),
    ).resolves.toBeTruthy();
  });

  it("refuses to revoke twice", async () => {
    const certificate = await issueCertificate({ actor: signer, algorithm: "ED25519" });
    await revokeCertificate({ actor: admin, certificateId: certificate.id });
    await expect(
      revokeCertificate({ actor: admin, certificateId: certificate.id }),
    ).rejects.toThrow(/REVOKED -> REVOKED/);
  });
});

describe("authorisation on issuance", () => {
  it("Section 6: a VIEWER cannot issue a certificate", async () => {
    await expect(
      issueCertificate({ actor: viewer, algorithm: "ECDSA_P256" }),
    ).rejects.toThrow(AuthorizationError);
  });

  it("a SIGNER cannot issue a certificate for someone else, and is told it is forbidden", async () => {
    const attempt = () =>
      issueCertificate({ actor: signer, algorithm: "RSA", subjectUserId: admin.userId });
    await expect(attempt()).rejects.toThrow(AuthorizationError);
    await expect(attempt()).rejects.toThrow(/Only an ADMIN/);
  });

  it("an ADMIN can issue on another user's behalf", async () => {
    const certificate = await issueCertificate({
      actor: admin,
      algorithm: "ECDSA_P256",
      subjectUserId: signer.userId,
    });
    expect(certificate.subjectUserId).toBe(signer.userId);
  });
});

describe("signable certificates", () => {
  it("lists only the actor's own active, in-window certificates", async () => {
    const active = await issueCertificate({ actor: signer, algorithm: "ED25519" });
    const revoked = await issueCertificate({ actor: signer, algorithm: "RSA" });
    await revokeCertificate({ actor: admin, certificateId: revoked.id });

    const expired = await issueCertificate({
      actor: signer,
      algorithm: "ECDSA_P256",
      notBefore: new Date("2020-01-01"),
      notAfter: new Date("2021-01-01"),
    });

    const ids = (await signableCertificates(signer)).map((certificate) => certificate.id);
    expect(ids).toContain(active.id);
    expect(ids).not.toContain(revoked.id);
    expect(ids).not.toContain(expired.id);
  });
});
