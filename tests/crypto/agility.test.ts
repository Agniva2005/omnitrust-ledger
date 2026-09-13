// Empirical test of the crypto-agility claim.
//
// The claim is that adding a signature algorithm needs one provider file plus one registry
// entry, and no change to document management, PKI, verification or storage. This test
// performs exactly that addition -- a real ML-DSA-44 provider, which the production
// registry does not contain, added as one extra registry entry -- and then runs the
// unmodified service code end to end. Nothing below lib/crypto/registry is mocked.
import { AsnConvert } from "@peculiar/asn1-schema";
import { SubjectPublicKeyInfo } from "@peculiar/asn1-x509";
import { beforeAll, describe, expect, it, vi } from "vitest";
import type { Actor } from "@/lib/auth/rbac";
import { ALGORITHMS, orchestrator, type Algorithm } from "@/lib/crypto/orchestrator";
import { pemBody } from "@/lib/crypto/pem";
import { prisma } from "@/lib/db";
import { uploadDocument } from "@/lib/documents/service";
import { signDocument } from "@/lib/documents/signing";
import { writeBlob } from "@/lib/documents/storage";
import { verifyDocument } from "@/lib/documents/verification";
import { ensureRootCa } from "@/lib/pki/ca";
import { issueCertificate, publicKeyPemFromCertificate } from "@/lib/pki/certificates";
import { validateCertificate } from "@/lib/pki/validation";
import { seedUsers } from "@/prisma/fixtures";
import { findBoundaryViolations } from "@/scripts/check-crypto-boundary";
import { resetDatabase } from "@/tests/helpers/db";
import { ensureMasterKey } from "@/tests/helpers/master-key";

// The one change: the production registry plus one entry.
vi.mock("@/lib/crypto/registry", async (importOriginal) => {
  const original = await importOriginal<typeof import("@/lib/crypto/registry")>();
  const { mlDsa44TestProvider, TEST_ALGORITHM_ID } = await import(
    "@/tests/crypto/support/ml-dsa-44-test-provider"
  );
  const providers = { ...original.PROVIDERS, [TEST_ALGORITHM_ID]: mlDsa44TestProvider };
  return { ...original, PROVIDERS: providers, registry: original.createRegistry(providers) };
});

const NEW_ALGORITHM = "TEST_ML_DSA_44" as Algorithm;

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

async function uploadAndSign(certificateId: string, contents: string) {
  const document = await uploadDocument({
    actor: signer,
    filename: `agility-${Math.random().toString(36).slice(2)}.txt`,
    mimeType: "text/plain",
    bytes: Buffer.from(contents),
  });
  await signDocument({ actor: signer, documentId: document.id, certificateId });
  return document;
}

describe("adding a provider with one registry entry", () => {
  it("is discovered from the registry by every consumer, not declared anywhere else", async () => {
    const actual = await vi.importActual<typeof import("@/lib/crypto/registry")>(
      "@/lib/crypto/registry",
    );
    expect([...ALGORITHMS]).toEqual([...Object.keys(actual.PROVIDERS), NEW_ALGORITHM]);
    expect(orchestrator.describe(NEW_ALGORITHM).securityClass).toBe("post-quantum");
  });

  it("is a real ML-DSA-44 implementation, not a stand-in", async () => {
    const { publicKeyPem, privateKeyPem } = await orchestrator.generateKeyPair(NEW_ALGORITHM);
    const spki = AsnConvert.parse(pemBody(publicKeyPem), SubjectPublicKeyInfo);
    expect(spki.algorithm.algorithm).toBe("2.16.840.1.101.3.4.3.17"); // id-ml-dsa-44
    expect(spki.subjectPublicKey.byteLength).toBe(1312); // FIPS 204 Table 2

    const message = Buffer.from("post-quantum agility");
    const signature = await orchestrator.sign({ algorithm: NEW_ALGORITHM, message, privateKeyPem });
    expect(signature.length).toBe(2420); // FIPS 204 Table 2

    const verify = (bytes: Uint8Array) =>
      orchestrator.verify({ algorithm: NEW_ALGORITHM, message, signature: bytes, publicKeyPem });
    expect(await verify(signature)).toBe(true);
    const altered = Buffer.from(signature);
    altered[100] ^= 0x01;
    expect(await verify(altered)).toBe(false);
  });

  it("is certified, used to sign, and verified VALID by the unmodified PKI and document code", async () => {
    const certificate = await issueCertificate({ actor: signer, algorithm: NEW_ALGORITHM });
    expect((await validateCertificate(certificate)).valid).toBe(true);
    expect(orchestrator.identifyPublicKey(publicKeyPemFromCertificate(certificate.certPem))).toBe(
      NEW_ALGORITHM,
    );

    const document = await uploadAndSign(certificate.id, "Signed under an algorithm added by one registry entry.");
    const signature = await prisma.signature.findFirstOrThrow({
      where: { documentVersion: { documentId: document.id } },
    });
    expect(signature.algorithm).toBe(NEW_ALGORITHM);
    expect(signature.signatureBytes.length).toBe(2420);

    const result = await verifyDocument(verifier, document.id);
    expect(result.outcome).toBe("VALID");
    expect(result.steps.every((step) => step.status === "PASS")).toBe(true);
  });

  it("gets tamper detection for free", async () => {
    const certificate = await issueCertificate({ actor: signer, algorithm: NEW_ALGORITHM });
    const document = await uploadAndSign(certificate.id, "Amount due: 100.00");
    const version = await prisma.documentVersion.findFirstOrThrow({
      where: { documentId: document.id },
    });
    await writeBlob(version.storagePath, Buffer.from("Amount due: 900.00"));

    const result = await verifyDocument(verifier, document.id);
    expect(result.outcome).toBe("INVALID");
    expect(result.reason).toBe("HASH_MISMATCH");
  });

  it("gets algorithm-confusion protection for free", async () => {
    const certificate = await issueCertificate({ actor: signer, algorithm: NEW_ALGORITHM });
    const classical = await issueCertificate({ actor: signer, algorithm: ALGORITHMS[0] });
    const document = await uploadAndSign(certificate.id, "Pointed at a classical certificate.");

    await prisma.signature.updateMany({
      where: { documentVersion: { documentId: document.id } },
      data: { certificateId: classical.id },
    });

    const result = await verifyDocument(verifier, document.id);
    expect(result.outcome).toBe("INVALID");
    expect(result.reason).toBe("ALGORITHM_MISMATCH");
  });

  it("required no algorithm-specific code outside lib/crypto", () => {
    // The boundary checker reads algorithm identifiers from the (extended) registry, so it
    // is also looking for the new identifier written anywhere outside the crypto layer.
    expect(ALGORITHMS).toContain(NEW_ALGORITHM);
    expect(findBoundaryViolations()).toEqual([]);
  });
});
