import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { ConflictError } from "@/lib/api";
import { AuthorizationError, type Actor } from "@/lib/auth/rbac";
import { sha256Hex } from "@/lib/crypto/hash";
import { orchestrator } from "@/lib/crypto/orchestrator";
import { ALGORITHMS, type Algorithm } from "@/lib/crypto/types";
import { prisma } from "@/lib/db";
import { addDocumentVersion, uploadDocument } from "@/lib/documents/service";
import { signDocument } from "@/lib/documents/signing";
import { ensureRootCa } from "@/lib/pki/ca";
import {
  issueCertificate,
  publicKeyPemFromCertificate,
  revokeCertificate,
} from "@/lib/pki/certificates";
import { seedUsers } from "@/prisma/fixtures";
import { resetDatabase } from "@/tests/helpers/db";
import { ensureMasterKey } from "@/tests/helpers/master-key";

let admin: Actor;
let signer: Actor;
let verifier: Actor;
const certificates = {} as Record<Algorithm, Awaited<ReturnType<typeof issueCertificate>>>;

beforeAll(async () => {
  ensureMasterKey();
  await resetDatabase();
  await seedUsers();
  await ensureRootCa();

  const users = await prisma.user.findMany();
  const id = (email: string) => users.find((user) => user.email === email)!.id;
  admin = { userId: id("admin@demo"), email: "admin@demo", role: "ADMIN" };
  signer = { userId: id("signer@demo"), email: "signer@demo", role: "SIGNER" };
  verifier = { userId: id("verifier@demo"), email: "verifier@demo", role: "VERIFIER" };

  for (const algorithm of ALGORITHMS) {
    certificates[algorithm] = await issueCertificate({ actor: signer, algorithm });
  }
}, 120_000);

beforeEach(async () => {
  await prisma.signature.deleteMany();
  await prisma.documentVersion.deleteMany();
  await prisma.document.deleteMany();
});

function upload(contents: string, filename = "contract.txt") {
  return uploadDocument({
    actor: signer,
    filename,
    mimeType: "text/plain",
    bytes: Buffer.from(contents),
  });
}

describe.each(ALGORITHMS)("signing under %s", (algorithm) => {
  it("stores a signature over the current version hash and advances the lifecycle", async () => {
    const document = await upload(`signed under ${algorithm}`, `${algorithm}.txt`);
    const result = await signDocument({
      actor: signer,
      documentId: document.id,
      certificateId: certificates[algorithm].id,
    });

    expect(result.signature.algorithm).toBe(algorithm);
    expect(result.signedHash).toBe(document.currentHash);
    expect(result.documentStatus).toBe("STORED");

    const stored = await prisma.signature.findUniqueOrThrow({
      where: { id: result.signature.id },
      include: { documentVersion: true, certificate: true },
    });
    expect(stored.documentVersion.hash).toBe(document.currentHash);
    expect(stored.certificateId).toBe(certificates[algorithm].id);
    expect(stored.signedByUserId).toBe(signer.userId);
  });

  it("produces a signature that verifies against the certificate's public key", async () => {
    const document = await upload(`verify me under ${algorithm}`, `${algorithm}-verify.txt`);
    const { signature } = await signDocument({
      actor: signer,
      documentId: document.id,
      certificateId: certificates[algorithm].id,
    });

    const verified = await orchestrator.verify({
      algorithm,
      digest: Buffer.from(document.currentHash, "hex"),
      signature: signature.signatureBytes,
      publicKeyPem: publicKeyPemFromCertificate(certificates[algorithm].certPem),
    });
    expect(verified).toBe(true);
  });

  it("signs the raw 32 bytes of the hash, not its hex text", async () => {
    const document = await upload(`raw bytes under ${algorithm}`, `${algorithm}-raw.txt`);
    const { signature } = await signDocument({
      actor: signer,
      documentId: document.id,
      certificateId: certificates[algorithm].id,
    });

    const publicKeyPem = publicKeyPemFromCertificate(certificates[algorithm].certPem);
    expect(
      await orchestrator.verify({
        algorithm,
        digest: Buffer.from(document.currentHash, "hex"),
        signature: signature.signatureBytes,
        publicKeyPem,
      }),
    ).toBe(true);
    // The 64-character hex string is a different message and must not verify.
    expect(
      await orchestrator.verify({
        algorithm,
        digest: Buffer.from(document.currentHash, "utf8"),
        signature: signature.signatureBytes,
        publicKeyPem,
      }),
    ).toBe(false);
  });

  it("records the signature size the algorithm specifies", async () => {
    const document = await upload(`size under ${algorithm}`, `${algorithm}-size.txt`);
    const { signature } = await signDocument({
      actor: signer,
      documentId: document.id,
      certificateId: certificates[algorithm].id,
    });

    const expected = orchestrator.describe(algorithm).signatureByteLength;
    if (expected === null) {
      expect(signature.signatureBytes.length).toBeGreaterThanOrEqual(68);
      expect(signature.signatureBytes.length).toBeLessThanOrEqual(72);
    } else {
      expect(signature.signatureBytes.length).toBe(expected);
    }
  });
});

describe("the same document hash signed across all three algorithms", () => {
  it("gives three different signatures that each verify (Phase 5 DoD)", async () => {
    const results = [];
    for (const algorithm of ALGORITHMS) {
      const document = await upload(`shared text for ${algorithm}`, `${algorithm}-doc.txt`);
      const { signature } = await signDocument({
        actor: signer,
        documentId: document.id,
        certificateId: certificates[algorithm].id,
      });
      results.push({ algorithm, document, signature });
    }

    for (const { algorithm, document, signature } of results) {
      expect(
        await orchestrator.verify({
          algorithm,
          digest: Buffer.from(document.currentHash, "hex"),
          signature: signature.signatureBytes,
          publicKeyPem: publicKeyPemFromCertificate(certificates[algorithm].certPem),
        }),
      ).toBe(true);
    }

    const distinct = new Set(
      results.map((result) => Buffer.from(result.signature.signatureBytes).toString("hex")),
    );
    expect(distinct.size).toBe(ALGORITHMS.length);
  });
});

describe("preconditions", () => {
  it("Section 6: a VERIFIER cannot sign", async () => {
    const document = await upload("verifier attempt");
    await expect(
      signDocument({
        actor: verifier,
        documentId: document.id,
        certificateId: certificates.RSA.id,
      }),
    ).rejects.toThrow(AuthorizationError);
  });

  it("refuses a second signature on the same version, pointing at versioning", async () => {
    const document = await upload("sign once");
    await signDocument({
      actor: signer,
      documentId: document.id,
      certificateId: certificates.ED25519.id,
    });

    await expect(
      signDocument({
        actor: signer,
        documentId: document.id,
        certificateId: certificates.RSA.id,
      }),
    ).rejects.toThrow(ConflictError);
    await expect(
      signDocument({
        actor: signer,
        documentId: document.id,
        certificateId: certificates.RSA.id,
      }),
    ).rejects.toThrow(/Upload a new version/);
  });

  it("allows signing a new version after one was already signed", async () => {
    const document = await upload("first version");
    await signDocument({
      actor: signer,
      documentId: document.id,
      certificateId: certificates.ED25519.id,
    });

    await addDocumentVersion(signer, document.id, "contract.txt", Buffer.from("second version"));

    const result = await signDocument({
      actor: signer,
      documentId: document.id,
      certificateId: certificates.RSA.id,
    });
    expect(result.signedHash).toBe(sha256Hex(Buffer.from("second version")));
    expect(await prisma.signature.count({ where: { documentVersion: { documentId: document.id } } })).toBe(2);
  });

  it("refuses a revoked certificate", async () => {
    const certificate = await issueCertificate({ actor: signer, algorithm: "ECDSA_P256" });
    await revokeCertificate({ actor: admin, certificateId: certificate.id });

    const document = await upload("revoked cert attempt");
    await expect(
      signDocument({ actor: signer, documentId: document.id, certificateId: certificate.id }),
    ).rejects.toThrow(/CERTIFICATE_REVOKED/);
  });

  it("refuses an expired certificate", async () => {
    const certificate = await issueCertificate({
      actor: signer,
      algorithm: "ED25519",
      notBefore: new Date("2024-01-01T00:00:00Z"),
      notAfter: new Date("2024-02-01T00:00:00Z"),
    });

    const document = await upload("expired cert attempt");
    await expect(
      signDocument({ actor: signer, documentId: document.id, certificateId: certificate.id }),
    ).rejects.toThrow(/CERTIFICATE_EXPIRED/);
  });

  it("refuses a certificate belonging to another user", async () => {
    const adminCertificate = await issueCertificate({ actor: admin, algorithm: "ED25519" });
    const document = await upload("someone else's certificate");
    const attempt = () =>
      signDocument({ actor: signer, documentId: document.id, certificateId: adminCertificate.id });
    await expect(attempt()).rejects.toThrow(AuthorizationError);
    await expect(attempt()).rejects.toThrow(/issued to you/);
  });

  it("refuses to sign when the stored bytes no longer match the recorded hash", async () => {
    const document = await upload("about to be tampered with");
    await prisma.documentVersion.updateMany({
      where: { documentId: document.id },
      data: { hash: "0".repeat(64) },
    });

    await expect(
      signDocument({
        actor: signer,
        documentId: document.id,
        certificateId: certificates.ED25519.id,
      }),
    ).rejects.toThrow(/no longer match/);
  });
});
