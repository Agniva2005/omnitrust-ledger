// A post-quantum trust chain chosen by installation policy alone: the root CA, the Time-Stamp
// Authority and the audit signer switched to a registered post-quantum algorithm, with nothing else
// changed. Certificates the CA signs are also checked by OpenSSL 3.5 through node:crypto's
// X509Certificate, independently of the WebCrypto path that produced them. Algorithms are chosen
// from the registry by security class, never named here.
import { X509Certificate } from "node:crypto";
import { AsnConvert } from "@peculiar/asn1-schema";
import { Certificate as AsnCertificate } from "@peculiar/asn1-x509";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { Actor } from "@/lib/auth/rbac";
import { sha256 } from "@/lib/crypto/hash";
import { ALGORITHMS, orchestrator, type Algorithm } from "@/lib/crypto/orchestrator";
import { pemBody, toPem } from "@/lib/crypto/pem";
import { prisma } from "@/lib/db";
import { uploadDocument } from "@/lib/documents/service";
import { signDocument } from "@/lib/documents/signing";
import { verifyDocument } from "@/lib/documents/verification";
import { createAuditCheckpoint, verifyAuditLog } from "@/lib/pki/audit-checkpoints";
import { ensureRootCa, getRootCa } from "@/lib/pki/ca";
import { issueCertificate, revokeCertificate } from "@/lib/pki/certificates";
import { verifyDetachedSignature } from "@/lib/pki/cms-signature";
import { RevocationStatusUnavailableError, authenticateCrl, issueCrl } from "@/lib/pki/crl";
import { CA_ALGORITHM, PKI_POLICY_VARIABLES, PkiPolicyError, caAlgorithm, tsaAlgorithm } from "@/lib/pki/policy";
import { issueTimestampToken, verifyTimestampToken } from "@/lib/pki/tsa";
import { validateCertificate } from "@/lib/pki/validation";
import { seedUsers } from "@/prisma/fixtures";
import { resetDatabase } from "@/tests/helpers/db";
import { ensureMasterKey } from "@/tests/helpers/master-key";

const describeAlgorithm = (algorithm: Algorithm) => orchestrator.describe(algorithm);
const PQ_ISSUER = ALGORITHMS.find((algorithm) => describeAlgorithm(algorithm).securityClass === "post-quantum" && describeAlgorithm(algorithm).capabilities.x509Issuer)!;
const HYBRID = ALGORITHMS.find((algorithm) => describeAlgorithm(algorithm).securityClass === "hybrid");
const NON_ISSUER = ALGORITHMS.find((algorithm) => !describeAlgorithm(algorithm).capabilities.x509Issuer);

function setPolicy(values: Partial<Record<keyof typeof PKI_POLICY_VARIABLES, string>>) {
  for (const [service, value] of Object.entries(values)) process.env[PKI_POLICY_VARIABLES[service as keyof typeof PKI_POLICY_VARIABLES]] = value;
}

function clearPolicy() {
  for (const variable of Object.values(PKI_POLICY_VARIABLES)) delete process.env[variable];
}

/** OpenSSL, through node:crypto, verifies the certificate's signature under the CA certificate's key. */
function opensslVerifies(certPem: string, caPem: string): boolean {
  return new X509Certificate(certPem).verify(new X509Certificate(caPem).publicKey);
}

function flipLastByte(der: Uint8Array): Uint8Array {
  const copy = new Uint8Array(der);
  copy[copy.length - 8] ^= 0x01;
  return copy;
}

async function seededActors() {
  await seedUsers();
  const users = await prisma.user.findMany();
  const actorFor = (email: string, role: Actor["role"]): Actor => ({ userId: users.find((user) => user.email === email)!.id, email, role });
  return { admin: actorFor("admin@demo", "ADMIN"), signer: actorFor("signer@demo", "SIGNER"), verifier: actorFor("verifier@demo", "VERIFIER") };
}

it("the registry offers a post-quantum certificate issuer", () => {
  expect(PQ_ISSUER).toBeDefined();
});

describe("trust-service algorithm policy", () => {
  afterAll(clearPolicy);

  it("keeps the classical default when nothing is configured", () => {
    clearPolicy();
    expect(caAlgorithm()).toBe(CA_ALGORITHM);
  });

  it("refuses an unregistered algorithm", () => {
    setPolicy({ ca: "NOT_A_REGISTERED_ALGORITHM" });
    expect(() => caAlgorithm()).toThrow(PkiPolicyError);
  });

  it.skipIf(!NON_ISSUER)("refuses a CA algorithm that cannot sign certificates", () => {
    setPolicy({ ca: NON_ISSUER! });
    expect(() => caAlgorithm()).toThrow(/cannot sign X.509 certificates/);
  });

  it.skipIf(!HYBRID)("accepts a hybrid algorithm for the Time-Stamp Authority, whose tokens are CMS", () => {
    setPolicy({ tsa: HYBRID! });
    expect(tsaAlgorithm()).toBe(HYBRID);
  });
});

describe("a trust chain whose CA, Time-Stamp Authority and audit signer are post-quantum", () => {
  let actors: Awaited<ReturnType<typeof seededActors>>;

  beforeAll(async () => {
    ensureMasterKey();
    await resetDatabase();
    actors = await seededActors();
    setPolicy({ ca: PQ_ISSUER, tsa: PQ_ISSUER, auditSigner: PQ_ISSUER });
    await ensureRootCa();
  }, 120_000);

  afterAll(async () => {
    clearPolicy();
    await resetDatabase();
  });

  it("creates the root CA under the configured algorithm, self-signed with absent signature parameters (RFC 9881)", async () => {
    const ca = await getRootCa();
    expect(ca.algorithm).toBe(PQ_ISSUER);
    const parsed = AsnConvert.parse(pemBody(ca.certPem), AsnCertificate);
    expect(parsed.signatureAlgorithm.algorithm).toBe(describeAlgorithm(PQ_ISSUER).oids.signature);
    expect(parsed.signatureAlgorithm.parameters ?? null).toBeNull();
    expect(opensslVerifies(ca.certPem, ca.certPem)).toBe(true);
  });

  it("issues a certificate for every certifiable algorithm that validates and that OpenSSL verifies", async () => {
    const ca = await getRootCa();
    for (const algorithm of ALGORITHMS.filter((candidate) => describeAlgorithm(candidate).capabilities.x509Subject)) {
      const certificate = await issueCertificate({ actor: actors.signer, algorithm });
      const validation = await validateCertificate(certificate);
      expect(validation, algorithm).toMatchObject({ valid: true });
      expect(opensslVerifies(certificate.certPem, ca.certPem), algorithm).toBe(true);
    }
  }, 120_000);

  it("rejects a certificate whose CA signature was altered, in both implementations", async () => {
    const ca = await getRootCa();
    const certificate = await issueCertificate({ actor: actors.signer, algorithm: PQ_ISSUER });
    const tampered = toPem("CERTIFICATE", flipLastByte(pemBody(certificate.certPem)));
    const validation = await validateCertificate({ ...certificate, certPem: tampered });
    expect(validation).toMatchObject({ valid: false, reason: "CERTIFICATE_CHAIN_INVALID" });
    expect(opensslVerifies(tampered, ca.certPem)).toBe(false);
  });

  it("signs and time-stamps a document that verifies VALID, and INVALID once its key is reported compromised", async () => {
    const certificate = await issueCertificate({ actor: actors.signer, algorithm: PQ_ISSUER });
    const bytes = Buffer.from(`post-quantum chain ${Date.now()}`);
    const document = await uploadDocument({ actor: actors.signer, filename: "pq-chain.txt", mimeType: "text/plain", bytes });
    await signDocument({ actor: actors.signer, documentId: document.id, certificateId: certificate.id });

    const authority = await prisma.timestampAuthority.findFirstOrThrow({ where: { status: "ACTIVE" } });
    expect(authority.algorithm).toBe(PQ_ISSUER);

    const valid = await verifyDocument(actors.verifier, document.id);
    expect(valid.outcome, JSON.stringify(valid.steps)).toBe("VALID");

    const signature = await prisma.signature.findFirstOrThrow({ where: { certificateId: certificate.id } });
    expect((await verifyDetachedSignature(signature.cmsSignature!, bytes)).status).toBe("VALID");

    await revokeCertificate({ actor: actors.admin, certificateId: certificate.id, reason: "keyCompromise" });
    const revoked = await verifyDocument(actors.verifier, document.id);
    expect(revoked).toMatchObject({ outcome: "INVALID", reason: "CERTIFICATE_REVOKED" });
  }, 120_000);

  it("authenticates its own CRL and treats an altered one as unavailable, never as unrevoked", async () => {
    const list = await issueCrl();
    await expect(authenticateCrl(list.der)).resolves.toMatchObject({ crlNumber: list.crlNumber });
    await expect(authenticateCrl(flipLastByte(list.der))).rejects.toThrow(RevocationStatusUnavailableError);
  });

  it("signs an audit checkpoint that reconciles with the log", async () => {
    await createAuditCheckpoint(actors.admin);
    const signer = await prisma.auditSigner.findFirstOrThrow({ where: { status: "ACTIVE" } });
    expect(signer.algorithm).toBe(PQ_ISSUER);
    const verification = await verifyAuditLog();
    expect(verification.problems).toEqual([]);
    expect(verification.valid).toBe(true);
  }, 60_000);
});

describe.skipIf(!HYBRID)("a hybrid Time-Stamp Authority under a post-quantum CA", () => {
  beforeAll(async () => {
    ensureMasterKey();
    await resetDatabase();
    await seedUsers();
    setPolicy({ ca: PQ_ISSUER, tsa: HYBRID! });
    await ensureRootCa();
  }, 60_000);

  afterAll(async () => {
    clearPolicy();
    await resetDatabase();
  });

  it("issues a token that verifies as a trusted proof of existence", async () => {
    const imprint = sha256(Buffer.from("hybrid time-stamp"));
    const issued = await issueTimestampToken({ imprint });
    const authority = await prisma.timestampAuthority.findFirstOrThrow({ where: { id: issued.authorityId } });
    expect(authority.algorithm).toBe(HYBRID);
    const verification = await verifyTimestampToken(issued.token, imprint);
    expect(verification.status, JSON.stringify(verification.checks)).toBe("VALID");
    expect(await verifyTimestampToken(issued.token, sha256(Buffer.from("other data")))).toMatchObject({ status: "INVALID" });
  }, 60_000);
});
