// Regression for an algorithm-confusion flaw found during the Phase 2 upgrade.
//
// OpenSSL follows the type of whatever key it is handed and ignores algorithm-specific
// options that do not apply. Before providers checked key types, the RSA-PSS provider
// accepted a genuine ECDSA signature made with an ECDSA key, and the ECDSA provider
// accepted an RSA PKCS#1 v1.5 signature. A document signed under ECDSA whose signature and
// certificate rows were relabelled "RSA" therefore verified as an authentic RSA-PSS
// signature. Two independent controls now refuse it: verification identifies the
// algorithm from the key material, and each provider refuses keys that are not its own.
import { sign as opensslSign } from "node:crypto";
import { beforeAll, describe, expect, it } from "vitest";
import type { Actor } from "@/lib/auth/rbac";
import { orchestrator } from "@/lib/crypto/orchestrator";
import { prisma } from "@/lib/db";
import { uploadDocument } from "@/lib/documents/service";
import { signDocument } from "@/lib/documents/signing";
import { verifyDocument } from "@/lib/documents/verification";
import { ensureRootCa } from "@/lib/pki/ca";
import {
  issueCertificate,
  privateKeyPemFor,
  publicKeyPemFromCertificate,
} from "@/lib/pki/certificates";
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
  const actorFor = (email: string, role: Actor["role"]): Actor => ({
    userId: users.find((user) => user.email === email)!.id,
    email,
    role,
  });
  signer = actorFor("signer@demo", "SIGNER");
  verifier = actorFor("verifier@demo", "VERIFIER");
}, 60_000);

describe("a genuine signature relabelled as a different algorithm", () => {
  it("is refused when an ECDSA signature and its certificate are relabelled as RSA-PSS", async () => {
    const certificate = await issueCertificate({ actor: signer, algorithm: "ECDSA_P256" });
    const document = await uploadDocument({
      actor: signer,
      filename: "relabelled.txt",
      mimeType: "text/plain",
      bytes: Buffer.from("Signed under ECDSA, later claimed to be RSA-PSS."),
    });
    await signDocument({ actor: signer, documentId: document.id, certificateId: certificate.id });
    expect((await verifyDocument(verifier, document.id)).outcome).toBe("VALID");

    // Relabel both rows. The signature bytes and the certificate bytes are untouched and genuine.
    await prisma.certificate.update({ where: { id: certificate.id }, data: { algorithm: "RSA" } });
    await prisma.signature.updateMany({
      where: { documentVersion: { documentId: document.id } },
      data: { algorithm: "RSA" },
    });

    const result = await verifyDocument(verifier, document.id);
    expect(result.outcome).toBe("INVALID");
    expect(result.reason).toBe("ALGORITHM_MISMATCH");
    expect(result.steps.find((step) => step.id === "public-key")?.detail).toContain(
      "carries a ECDSA_P256 key",
    );
    expect(result.steps.find((step) => step.id === "signature-verification")?.status).toBe("SKIPPED");
  });
});

describe("the providers refuse keys that are not their own, independently of the workflow", () => {
  it("the RSA-PSS provider refuses a genuine ECDSA signature presented with its ECDSA key", async () => {
    const certificate = await issueCertificate({ actor: signer, algorithm: "ECDSA_P256" });
    const message = Buffer.from("any message");
    const publicKeyPem = publicKeyPemFromCertificate(certificate.certPem);
    const signature = await orchestrator.sign({
      algorithm: "ECDSA_P256",
      message,
      privateKeyPem: privateKeyPemFor(certificate.keyPair),
    });

    expect(
      await orchestrator.verify({ algorithm: "ECDSA_P256", message, signature, publicKeyPem }),
    ).toBe(true);
    await expect(
      orchestrator.verify({ algorithm: "RSA", message, signature, publicKeyPem }),
    ).rejects.toThrow(/Not an RSA-3072 public key/);
  });

  it("the ECDSA provider refuses an RSA PKCS#1 v1.5 signature presented with its RSA key", async () => {
    const { publicKeyPem, privateKeyPem } = await orchestrator.generateKeyPair("RSA");
    const message = Buffer.from("legacy padding");
    // PKCS#1 v1.5, made directly with OpenSSL: no OmniTrust provider produces this padding.
    const pkcs1v15 = opensslSign("sha256", message, privateKeyPem);

    await expect(
      orchestrator.verify({ algorithm: "ECDSA_P256", message, signature: pkcs1v15, publicKeyPem }),
    ).rejects.toThrow(/Not an ECDSA P-256 public key/);
    // Nor does the RSA-PSS provider accept v1.5 padding.
    expect(
      await orchestrator.verify({ algorithm: "RSA", message, signature: pkcs1v15, publicKeyPem }),
    ).toBe(false);
  });

  it("the RSA-PSS provider refuses to produce a signature from an ECDSA private key", async () => {
    const certificate = await issueCertificate({ actor: signer, algorithm: "ECDSA_P256" });
    await expect(
      orchestrator.sign({
        algorithm: "RSA",
        message: Buffer.from("claimed RSA"),
        privateKeyPem: privateKeyPemFor(certificate.keyPair),
      }),
    ).rejects.toThrow(/Not an RSA-3072 private key/);
  });
});
