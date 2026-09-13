// Detached CMS signatures (RFC 5652): produced in the signing action, verified in-app, and
// checked by tools that share no code with this app. RSA-PSS and ECDSA are verified with
// `openssl cms -verify`; the OpenSSL CLI (3.2.4 and 3.4.0 checked) cannot process Ed25519 or ML-DSA CMS, so those
// signatures are checked against node:crypto's Ed25519 (the app signs Ed25519 with @noble)
// and @noble/post-quantum's ML-DSA (the app signs ML-DSA with OpenSSL).
import { spawnSync } from "node:child_process";
import { createHash, createPublicKey, verify as nodeVerify } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { CertificateChoices, CertificateSet, ContentInfo, SignedData } from "@peculiar/asn1-cms";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import { Certificate } from "@peculiar/asn1-x509";
import * as asn1js from "asn1js";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { Actor } from "@/lib/auth/rbac";
import { COOKIE_NAME, createSessionToken } from "@/lib/auth/session";
import { ALGORITHMS, orchestrator, type Algorithm } from "@/lib/crypto/orchestrator";
import { pemBody } from "@/lib/crypto/pem";
import { prisma } from "@/lib/db";
import { exportSignedDocument, safeFilename } from "@/lib/documents/export";
import { uploadDocument } from "@/lib/documents/service";
import { signDocument } from "@/lib/documents/signing";
import { ensureRootCa, getRootCa } from "@/lib/pki/ca";
import { issueCertificate } from "@/lib/pki/certificates";
import { ID_AA_SIGNATURE_TIME_STAMP_TOKEN, verifyDetachedSignature } from "@/lib/pki/cms-signature";
import { seedUsers } from "@/prisma/fixtures";
import { resetDatabase } from "@/tests/helpers/db";
import { ensureMasterKey } from "@/tests/helpers/master-key";

const session = vi.hoisted(() => ({ token: null as string | null }));
vi.mock("next/headers", () => ({
  cookies: async () => ({
    get: (name: string) =>
      name === COOKIE_NAME && session.token ? { name, value: session.token } : undefined,
  }),
}));
const { GET: exportEndpoint } = await import("@/app/api/documents/[id]/export/route");

const OPENSSL_AVAILABLE = spawnSync("openssl", ["version"]).status === 0;
const INTEROP_DIR = path.join(process.cwd(), "storage", "test", "openssl-cms");
const file = (name: string) => path.join(INTEROP_DIR, name);

const DIGEST_NAMES: Record<string, string> = {
  "2.16.840.1.101.3.4.2.1": "sha256",
  "2.16.840.1.101.3.4.2.3": "sha512",
};

let signer: Actor;
let viewer: Actor;
const certificates = {} as Record<Algorithm, Awaited<ReturnType<typeof issueCertificate>>>;

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
  viewer = actorFor("viewer@demo", "VIEWER");
  for (const algorithm of ALGORITHMS) {
    certificates[algorithm] = await issueCertificate({ actor: signer, algorithm });
  }
  fs.mkdirSync(INTEROP_DIR, { recursive: true });
}, 120_000);

beforeEach(async () => {
  await prisma.signature.deleteMany();
  await prisma.documentVersion.deleteMany();
  await prisma.document.deleteMany();
  session.token = null;
});

async function signed(algorithm: Algorithm, text = `CMS test document ${Math.random()}`) {
  const content = Buffer.from(text);
  const document = await uploadDocument({
    actor: signer,
    filename: `${algorithm}-${Math.random().toString(36).slice(2)}.txt`,
    mimeType: "text/plain",
    bytes: content,
  });
  await signDocument({ actor: signer, documentId: document.id, certificateId: certificates[algorithm].id });
  const signature = await prisma.signature.findFirstOrThrow({
    where: { documentVersion: { documentId: document.id } },
  });
  return { document, signature, content, cms: Buffer.from(signature.cmsSignature!) };
}

/** Re-encodes a SignedData after `mutate`, without re-signing. */
function reencode(der: Buffer, mutate: (signedData: SignedData) => void = () => {}): Buffer {
  const contentInfo = AsnConvert.parse(der, ContentInfo);
  const signedData = AsnConvert.parse(contentInfo.content, SignedData);
  mutate(signedData);
  return Buffer.from(
    AsnConvert.serialize(new ContentInfo({ contentType: contentInfo.contentType, content: AsnConvert.serialize(signedData) })),
  );
}

/**
 * The exact bytes the signer signed, taken from the file with asn1js rather than the app's
 * encoder: the [0] IMPLICIT signedAttrs element with its tag replaced by SET OF (RFC 5652 5.4).
 */
function signedBytes(der: Buffer) {
  const contentInfo = asn1js.fromBER(new Uint8Array(der)).result as asn1js.Sequence;
  const signedData = (contentInfo.valueBlock.value[1] as asn1js.Constructed).valueBlock.value[0] as asn1js.Sequence;
  const fields = signedData.valueBlock.value;
  const signerInfo = (fields[fields.length - 1] as asn1js.Set).valueBlock.value[0] as asn1js.Sequence;
  const attributes = signerInfo.valueBlock.value[3];
  expect(attributes.idBlock.tagClass).toBe(3);
  expect(attributes.idBlock.tagNumber).toBe(0);
  const signedAttrs = Buffer.from(attributes.valueBeforeDecodeView);
  signedAttrs[0] = 0x31;
  const signature = Buffer.from((signerInfo.valueBlock.value[5] as asn1js.OctetString).valueBlock.valueHexView);
  return { signedAttrs, signature };
}

describe("produced by the signing action", () => {
  it.each(ALGORITHMS)("gives every %s signature a detached CMS signature that verifies in-app", async (algorithm) => {
    const { cms, content } = await signed(algorithm);
    const result = await verifyDetachedSignature(cms, content);

    expect(result.status).toBe("VALID");
    expect(result.algorithm).toBe(algorithm);
    expect(result.signerSerial).toBe(certificates[algorithm].serialNumber.toUpperCase());
    expect(result.signingTime).not.toBeNull();
    expect(result.timestamp?.status).toBe("VALID");
  }, 30_000);

  it.each(ALGORITHMS)("uses the provider's CMS identifiers and keeps the %s content detached", async (algorithm) => {
    const { cms } = await signed(algorithm);
    const signedData = AsnConvert.parse(AsnConvert.parse(cms, ContentInfo).content, SignedData);
    const expected = orchestrator.describe(algorithm).cms;

    expect(signedData.encapContentInfo.eContent).toBeUndefined();
    expect(signedData.signerInfos[0].digestAlgorithm.algorithm).toBe(expected.digestAlgorithmOid);
    expect(signedData.signerInfos[0].signatureAlgorithm.algorithm).toBe(expected.signatureAlgorithmOid);
    // The signer's certificate and the CA certificate, so only the trust anchor is needed.
    expect(signedData.certificates).toHaveLength(2);
  }, 30_000);

  it("round-trips through re-encoding unchanged, so the rejections below come from the tampering", async () => {
    const { cms, content } = await signed("ECDSA_P256");
    const reencoded = reencode(cms);
    expect(reencoded.equals(cms)).toBe(true);
    expect((await verifyDetachedSignature(reencoded, content)).status).toBe("VALID");
  });
});

describe("rejections", () => {
  it.each(ALGORITHMS)("refuses altered %s document bytes at the message digest", async (algorithm) => {
    const { cms, content } = await signed(algorithm, "The agreed price is 1,000.");
    const altered = Buffer.from(content.toString().replace("1,000", "9,000"));

    const result = await verifyDetachedSignature(cms, altered);
    expect(result.status).toBe("INVALID");
    expect(result.checks.find((check) => check.step.startsWith("Message-digest"))?.passed).toBe(false);
  }, 30_000);

  it.each(ALGORITHMS)("refuses a flipped bit in the %s signature value", async (algorithm) => {
    const { cms, content } = await signed(algorithm);
    const tampered = reencode(cms, (signedData) => {
      const value = new Uint8Array(signedData.signerInfos[0].signature.buffer);
      value[value.length - 1] ^= 0x01;
      signedData.signerInfos[0].signature = new OctetString(value);
    });

    const result = await verifyDetachedSignature(tampered, content);
    expect(result.status).toBe("INVALID");
    expect(result.explanation).toMatch(/does not verify/);
  }, 30_000);

  it("refuses a signature whose signer certificate has been removed, or replaced by another certificate", async () => {
    const { cms, content } = await signed("ECDSA_P256");
    const other = await issueCertificate({ actor: signer, algorithm: "ECDSA_P256" });
    const ca = new CertificateChoices({ certificate: AsnConvert.parse(pemBody((await getRootCa()).certPem), Certificate) });
    const replacement = new CertificateChoices({ certificate: AsnConvert.parse(pemBody(other.certPem), Certificate) });

    const removed = reencode(cms, (signedData) => {
      signedData.certificates = new CertificateSet([ca]);
    });
    const replaced = reencode(cms, (signedData) => {
      signedData.certificates = new CertificateSet([ca, replacement]);
    });

    for (const tampered of [removed, replaced]) {
      const result = await verifyDetachedSignature(tampered, content);
      expect(result.status).toBe("INVALID");
      expect(result.explanation).toMatch(/does not include the certificate of its signer/);
    }
  }, 30_000);

  it("refuses a signature made over a different document", async () => {
    const first = await signed("ED25519", "Document A.");
    const second = await signed("ED25519", "Document B.");
    expect((await verifyDetachedSignature(first.cms, second.content)).status).toBe("INVALID");
  });

  it("refuses bytes that are not CMS at all", async () => {
    const result = await verifyDetachedSignature(Buffer.from("not a signature"), Buffer.from("x"));
    expect(result.status).toBe("INVALID");
    expect(result.explanation).toMatch(/not a well-formed/);
  });
});

describe("independent verification outside this app's code", () => {
  const OPENSSL_CMS = ALGORITHMS.filter((algorithm) => orchestrator.describe(algorithm).interoperability.opensslCms);
  const INDEPENDENT: Partial<Record<Algorithm, (signedAttrs: Buffer, signature: Buffer, certificatePem: string) => boolean>> = {
    ED25519: (signedAttrs, signature, certificatePem) =>
      nodeVerify(null, signedAttrs, createPublicKey(certificatePem), signature),
    ML_DSA_65: (signedAttrs, signature, certificatePem) => {
      const spki = createPublicKey(certificatePem).export({ format: "der", type: "spki" });
      return ml_dsa65.verify(new Uint8Array(signature), new Uint8Array(signedAttrs), new Uint8Array(spki.subarray(-1952)));
    },
  };

  it("covers every registered algorithm with at least one independent check", () => {
    expect(OPENSSL_CMS).toEqual(expect.arrayContaining(["RSA", "ECDSA_P256"]));
    for (const algorithm of ALGORITHMS) {
      expect(OPENSSL_CMS.includes(algorithm) || INDEPENDENT[algorithm] !== undefined).toBe(true);
    }
  });

  it.runIf(OPENSSL_AVAILABLE).each(OPENSSL_CMS)(
    "`openssl cms -verify` accepts the %s signature with only the CA as trust anchor, and rejects altered content",
    async (algorithm) => {
      const { cms, content } = await signed(algorithm);
      fs.writeFileSync(file(`${algorithm}.p7s`), cms);
      fs.writeFileSync(file(`${algorithm}.txt`), content);
      fs.writeFileSync(file(`${algorithm}-altered.txt`), Buffer.concat([content, Buffer.from("!")]));
      fs.writeFileSync(file("ca.pem"), (await getRootCa()).certPem);

      const run = (contentFile: string) => {
        const result = spawnSync(
          "openssl",
          ["cms", "-verify", "-binary", "-inform", "DER", "-in", file(`${algorithm}.p7s`), "-content", contentFile, "-CAfile", file("ca.pem"), "-out", file(`${algorithm}.out`)],
          { encoding: "utf8" },
        );
        return { status: result.status, output: `${result.stdout}\n${result.stderr}` };
      };

      const good = run(file(`${algorithm}.txt`));
      expect(good.output).toContain("Verification successful");
      expect(good.status).toBe(0);

      const bad = run(file(`${algorithm}-altered.txt`));
      expect(bad.status).not.toBe(0);
      expect(bad.output).toContain("Verification failure");
    },
    30_000,
  );

  it.runIf(OPENSSL_AVAILABLE)("`openssl ts -verify` accepts the embedded signature time-stamp over the signature value", async () => {
    const { cms } = await signed("ECDSA_P256");
    const signerInfo = AsnConvert.parse(AsnConvert.parse(cms, ContentInfo).content, SignedData).signerInfos[0];
    const token = signerInfo.unsignedAttrs!.find((candidate) => candidate.attrType === ID_AA_SIGNATURE_TIME_STAMP_TOKEN)!;

    fs.writeFileSync(file("token.der"), Buffer.from(token.attrValues[0]));
    fs.writeFileSync(file("signature-value.bin"), Buffer.from(signerInfo.signature.buffer));
    fs.writeFileSync(file("ca.pem"), (await getRootCa()).certPem);

    const result = spawnSync(
      "openssl",
      ["ts", "-verify", "-token_in", "-in", file("token.der"), "-data", file("signature-value.bin"), "-CAfile", file("ca.pem")],
      { encoding: "utf8" },
    );
    expect(`${result.stdout}${result.stderr}`).toContain("Verification: OK");
  }, 30_000);

  it.each(ALGORITHMS.filter((algorithm) => INDEPENDENT[algorithm]))(
    "an independent %s implementation verifies the signature over the signed attributes, whose digest matches the document",
    async (algorithm) => {
      const { cms, content } = await signed(algorithm);
      const { signedAttrs, signature } = signedBytes(cms);
      const verify = INDEPENDENT[algorithm]!;
      const digest = createHash(DIGEST_NAMES[orchestrator.describe(algorithm).cms.digestAlgorithmOid]).update(content).digest();

      expect(signedAttrs.includes(digest)).toBe(true);
      expect(verify(signedAttrs, signature, certificates[algorithm].certPem)).toBe(true);

      const altered = Buffer.from(signedAttrs);
      altered[altered.length - 1] ^= 0x01;
      expect(verify(altered, signature, certificates[algorithm].certPem)).toBe(false);
    },
    30_000,
  );
});

describe("export", () => {
  it("lets any reader export the CMS signature, the document and the signer certificate, and audits it", async () => {
    const { document, cms, content } = await signed("RSA");

    const exported = await exportSignedDocument(viewer, document.id, "cms");
    expect(exported.bytes.equals(cms)).toBe(true);
    expect(exported.contentType).toBe("application/pkcs7-signature");
    expect(exported.filename).toMatch(/\.v1\.p7s$/);

    expect((await exportSignedDocument(viewer, document.id, "content")).bytes.equals(content)).toBe(true);
    expect((await exportSignedDocument(viewer, document.id, "certificate")).bytes.toString()).toBe(certificates.RSA.certPem);

    const entries = await prisma.auditLogEntry.findMany({ where: { action: "DOCUMENT_EXPORTED", targetId: document.id } });
    expect(entries.map((entry) => JSON.parse(entry.metadataJson).part).sort()).toEqual(["certificate", "cms", "content"]);
  }, 30_000);

  it("refuses to export a CMS signature that was never made", async () => {
    const { document, signature } = await signed("ECDSA_P256");
    await prisma.signature.update({ where: { id: signature.id }, data: { cmsSignature: null } });
    await expect(exportSignedDocument(viewer, document.id, "cms")).rejects.toThrow(/before CMS export/);
  });

  it("refuses to export a signature for an unsigned version", async () => {
    const document = await uploadDocument({
      actor: signer,
      filename: "unsigned.txt",
      mimeType: "text/plain",
      bytes: Buffer.from("never signed"),
    });
    await expect(exportSignedDocument(viewer, document.id, "cms")).rejects.toThrow(/has not been signed/);
  });

  it("makes filenames safe for a Content-Disposition header", () => {
    const name = safeFilename('..\\evil"name\r\n.txt');
    expect(name).not.toMatch(/["\\\r\n/]/);
    expect(name.startsWith(".")).toBe(false);
    expect(safeFilename("")).toBe("document");
  });

  describe("GET /api/documents/:id/export", () => {
    const request = (id: string, query: string) =>
      exportEndpoint(new Request(`http://localhost/api/documents/${id}/export?${query}`), {
        params: Promise.resolve({ id }),
      });

    it("requires a session", async () => {
      const { document } = await signed("ECDSA_P256");
      expect((await request(document.id, "part=cms")).status).toBe(401);
    });

    it("rejects an unknown part or version", async () => {
      const { document } = await signed("ECDSA_P256");
      session.token = await createSessionToken(viewer);
      expect((await request(document.id, "part=private-key")).status).toBe(400);
      expect((await request(document.id, "part=cms&version=0")).status).toBe(400);
      expect((await request(document.id, "part=cms&version=2")).status).toBe(404);
    });

    it("serves the CMS signature as a download that never renders inline", async () => {
      const { document, cms } = await signed("ECDSA_P256");
      session.token = await createSessionToken(viewer);

      const response = await request(document.id, "part=cms&version=1");
      expect(response.status).toBe(200);
      expect(response.headers.get("content-type")).toBe("application/pkcs7-signature");
      expect(response.headers.get("content-disposition")).toMatch(/^attachment; filename=".+\.v1\.p7s"$/);
      expect(response.headers.get("x-content-type-options")).toBe("nosniff");
      expect(Buffer.from(await response.arrayBuffer()).equals(cms)).toBe(true);

      const contentResponse = await request(document.id, "part=content");
      expect(contentResponse.headers.get("content-type")).toBe("application/octet-stream");
    });
  });
});
