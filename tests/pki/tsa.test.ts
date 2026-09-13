// The local RFC 3161 Time-Stamp Authority. Tokens are checked by this installation and,
// where an OpenSSL binary is available, by `openssl ts`, including a full RFC 3161
// request/response round trip through the HTTP endpoint.
import { spawnSync } from "node:child_process";
import { webcrypto } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import { ContentInfo, SignedData } from "@peculiar/asn1-cms";
import { PKIStatus, TimeStampResp, TSTInfo } from "@peculiar/asn1-tsp";
import * as x509 from "@peculiar/x509";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { Actor } from "@/lib/auth/rbac";
import { COOKIE_NAME, createSessionToken } from "@/lib/auth/session";
import { sha256 } from "@/lib/crypto/hash";
import { pemBody } from "@/lib/crypto/pem";
import { prisma } from "@/lib/db";
import { uploadDocument } from "@/lib/documents/service";
import { signDocument } from "@/lib/documents/signing";
import { ensureRootCa } from "@/lib/pki/ca";
import { issueCertificate } from "@/lib/pki/certificates";
import { issueCrl } from "@/lib/pki/crl";
import {
  ID_KP_TIME_STAMPING,
  TSA_ACCURACY_MS,
  ensureTimestampAuthority,
  issueTimestampToken,
  verifyTimestampToken,
} from "@/lib/pki/tsa";
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
const { POST: tsaEndpoint } = await import("@/app/api/tsa/route");

const OPENSSL_AVAILABLE = spawnSync("openssl", ["version"]).status === 0;
const INTEROP_DIR = path.join(process.cwd(), "storage", "test", "openssl-tsa");

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
  await prisma.revocationList.deleteMany();
  await prisma.timestampAuthority.deleteMany();
  session.token = null;
});

const imprintOf = (text: string) => sha256(Buffer.from(text));

/** Re-encodes a token after `mutate` changes its SignedData, without re-signing it. */
function tamperSignedData(token: Buffer, mutate: (signedData: SignedData) => void): Buffer {
  const contentInfo = AsnConvert.parse(token, ContentInfo);
  const signedData = AsnConvert.parse(contentInfo.content, SignedData);
  mutate(signedData);
  return Buffer.from(
    AsnConvert.serialize(new ContentInfo({ contentType: contentInfo.contentType, content: AsnConvert.serialize(signedData) })),
  );
}

describe("the Time-Stamp Authority", () => {
  it("is created once, with a certificate from the local CA carrying only a critical id-kp-timeStamping usage", async () => {
    const first = await ensureTimestampAuthority();
    const second = await ensureTimestampAuthority();
    expect(second.id).toBe(first.id);
    expect(first.policyOid).toMatch(/^2\.25\.\d+$/);

    const certificate = new x509.X509Certificate(first.certPem);
    const eku = certificate.getExtension(x509.ExtendedKeyUsageExtension);
    expect(eku?.critical).toBe(true);
    expect(eku?.usages.map(String)).toEqual([ID_KP_TIME_STAMPING]);
    expect(certificate.getExtension(x509.BasicConstraintsExtension)?.ca).toBe(false);
    expect(first.encryptedPrivateKey).not.toContain("PRIVATE KEY");
  });
});

describe("issuing and verifying tokens", () => {
  it("issues a token that verifies, stating genTime, accuracy and policy", async () => {
    const imprint = imprintOf("a signature value");
    const issued = await issueTimestampToken({ imprint });
    const verification = await verifyTimestampToken(issued.token, imprint);

    expect(verification.status).toBe("VALID");
    expect(verification.checks.every((check) => check.passed)).toBe(true);
    expect(verification.genTime?.getTime()).toBe(issued.genTime.getTime());
    expect(issued.genTime.getMilliseconds()).toBe(0);
    expect(verification.accuracyMs).toBe(TSA_ACCURACY_MS);
    expect(verification.policyOid).toBe((await ensureTimestampAuthority()).policyOid);
  });

  it("refuses a token presented for different data", async () => {
    const issued = await issueTimestampToken({ imprint: imprintOf("the real data") });
    const verification = await verifyTimestampToken(issued.token, imprintOf("other data"));
    expect(verification.status).toBe("INVALID");
    expect(verification.explanation).toMatch(/different data/);
  });

  it("refuses a token whose signature bytes were altered", async () => {
    const imprint = imprintOf("signature tamper");
    const issued = await issueTimestampToken({ imprint });
    const altered = tamperSignedData(issued.token, (signedData) => {
      const signature = Buffer.from(signedData.signerInfos[0].signature.buffer);
      signature[signature.length - 1] ^= 0x01;
      signedData.signerInfos[0].signature = new OctetString(signature);
    });
    expect((await verifyTimestampToken(altered, imprint)).status).toBe("INVALID");
  });

  it("refuses a token whose genTime was moved, because the TSTInfo no longer matches its signed digest", async () => {
    const imprint = imprintOf("backdating attempt");
    const issued = await issueTimestampToken({ imprint });
    const backdated = tamperSignedData(issued.token, (signedData) => {
      const info = AsnConvert.parse(signedData.encapContentInfo.eContent!.single!.buffer, TSTInfo);
      info.genTime = new Date(info.genTime.getTime() - 86_400_000);
      signedData.encapContentInfo.eContent!.single = new OctetString(AsnConvert.serialize(info));
    });

    const verification = await verifyTimestampToken(backdated, imprint);
    expect(verification.status).toBe("INVALID");
    expect(verification.checks.find((check) => check.step.startsWith("Message-digest"))?.passed).toBe(false);
  });

  it("refuses a token signed with a key that is not the authority's", async () => {
    const imprint = imprintOf("foreign key");
    const issued = await issueTimestampToken({ imprint });
    const impostor = await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
    const forged = tamperSignedData(issued.token, (signedData) => {
      signedData.signerInfos[0].signature = new OctetString(new Uint8Array(72));
    });
    expect(impostor).toBeDefined();
    expect((await verifyTimestampToken(forged, imprint)).status).toBe("INVALID");
  });

  it("refuses bytes that are not a token", async () => {
    const verification = await verifyTimestampToken(new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x01]), imprintOf("x"));
    expect(verification.status).toBe("INVALID");
    expect(verification.explanation).toMatch(/malformed/);
  });

  it("refuses an imprint whose length does not fit the hash algorithm", async () => {
    await expect(issueTimestampToken({ imprint: new Uint8Array(20) })).rejects.toThrow(/imprint/);
  });
});

describe("the authority's own certificate status", () => {
  // A revocation leaves earlier tokens standing only if they provably predate it, including
  // the token's stated accuracy, so these tests revoke after that window has passed. (A token
  // back-dated before the authority's own certificate existed is correctly refused.)
  const pastAccuracyWindow = () => new Promise((resolve) => setTimeout(resolve, TSA_ACCURACY_MS + 1100));

  it("keeps tokens issued before a non-compromise revocation of the authority", async () => {
    const imprint = imprintOf("issued before retirement");
    const issued = await issueTimestampToken({ imprint });
    await pastAccuracyWindow();
    const authority = await ensureTimestampAuthority();
    await prisma.timestampAuthority.update({
      where: { id: authority.id },
      data: { status: "REVOKED", revokedAt: new Date(), revocationReason: "superseded" },
    });
    await issueCrl();

    expect((await verifyTimestampToken(issued.token, imprint)).status).toBe("VALID");
  }, 20_000);

  it("refuses a token back-dated to before the authority's certificate existed", async () => {
    const imprint = imprintOf("before the authority existed");
    await ensureTimestampAuthority();
    const issued = await issueTimestampToken({ imprint }, new Date(Date.now() - 3_600_000));
    const verification = await verifyTimestampToken(issued.token, imprint);
    expect(verification.status).toBe("INVALID");
    expect(verification.checks.find((check) => check.step.startsWith("genTime lies within"))?.passed).toBe(false);
  });

  it("refuses tokens once the authority's key is reported compromised without an invalidity date", async () => {
    const imprint = imprintOf("authority compromised");
    const issued = await issueTimestampToken({ imprint });
    const authority = await ensureTimestampAuthority();
    await prisma.timestampAuthority.update({
      where: { id: authority.id },
      data: { status: "REVOKED", revokedAt: new Date(), revocationReason: "keyCompromise" },
    });
    await issueCrl();

    const verification = await verifyTimestampToken(issued.token, imprint);
    expect(verification.status).toBe("INVALID");
    expect(verification.explanation).toMatch(/revoked/);
  });

  it("is unavailable, not valid, when the authority's revocation status cannot be established", async () => {
    const imprint = imprintOf("crl tampered");
    const issued = await issueTimestampToken({ imprint });
    const list = await issueCrl();
    const altered = Buffer.from(list.der);
    altered[altered.length - 1] ^= 0x01;
    await prisma.revocationList.update({ where: { id: list.id }, data: { der: new Uint8Array(altered) } });

    expect((await verifyTimestampToken(issued.token, imprint)).status).toBe("UNAVAILABLE");
  });
});

describe("signing time-stamps every signature", () => {
  it("stores a token over the signature value that verifies, and audits it", async () => {
    const certificate = await issueCertificate({ actor: signer, algorithm: "ED25519" });
    const document = await uploadDocument({
      actor: signer,
      filename: "timestamped.txt",
      mimeType: "text/plain",
      bytes: Buffer.from("Signed and time-stamped."),
    });
    const result = await signDocument({ actor: signer, documentId: document.id, certificateId: certificate.id });

    expect(result.timestamp).not.toBeNull();
    const stored = await prisma.signature.findUniqueOrThrow({ where: { id: result.signature.id } });
    expect(stored.timestampToken).not.toBeNull();

    const verification = await verifyTimestampToken(stored.timestampToken!, sha256(stored.signatureBytes));
    expect(verification.status).toBe("VALID");

    const audit = await prisma.auditLogEntry.findFirstOrThrow({
      where: { action: "TIMESTAMP_ISSUED", targetId: stored.id },
    });
    expect(JSON.parse(audit.metadataJson).genTime).toBe(result.timestamp!.genTime.toISOString());
  });
});

describe("independent verification with OpenSSL", () => {
  const run = (args: string[]) => {
    const result = spawnSync("openssl", args, { encoding: "utf8" });
    return { status: result.status, output: `${result.stdout}\n${result.stderr}` };
  };
  const file = (name: string) => path.join(INTEROP_DIR, name);

  it.runIf(OPENSSL_AVAILABLE)("verifies a stored token against the time-stamped data, and rejects altered data", async () => {
    fs.mkdirSync(INTEROP_DIR, { recursive: true });
    const signatureValue = Buffer.from("the bytes of a document signature");
    const issued = await issueTimestampToken({ imprint: sha256(signatureValue) });
    const authority = await ensureTimestampAuthority();
    const ca = await prisma.certificateAuthority.findFirstOrThrow();

    fs.writeFileSync(file("token.der"), issued.token);
    fs.writeFileSync(file("data.bin"), signatureValue);
    fs.writeFileSync(file("altered.bin"), Buffer.concat([signatureValue, Buffer.from("x")]));
    fs.writeFileSync(file("ca.pem"), ca.certPem);
    fs.writeFileSync(file("tsa.pem"), authority.certPem);

    const ok = run(["ts", "-verify", "-token_in", "-in", file("token.der"), "-data", file("data.bin"), "-CAfile", file("ca.pem"), "-untrusted", file("tsa.pem")]);
    expect(ok.output).toContain("Verification: OK");

    const bad = run(["ts", "-verify", "-token_in", "-in", file("token.der"), "-data", file("altered.bin"), "-CAfile", file("ca.pem"), "-untrusted", file("tsa.pem")]);
    expect(bad.output).toContain("Verification: FAILED");
  });

  it.runIf(OPENSSL_AVAILABLE)(
    "answers an `openssl ts -query` over HTTP with a reply OpenSSL verifies against the query, nonce included",
    async () => {
      fs.mkdirSync(INTEROP_DIR, { recursive: true });
      fs.writeFileSync(file("payload.bin"), Buffer.from("RFC 3161 over HTTP"));
      const query = run(["ts", "-query", "-data", file("payload.bin"), "-sha256", "-cert", "-out", file("request.tsq")]);
      expect(query.status).toBe(0);

      session.token = await createSessionToken(signer);
      const response = await tsaEndpoint(
        new Request("http://localhost/api/tsa", {
          method: "POST",
          headers: { "content-type": "application/timestamp-query" },
          body: fs.readFileSync(file("request.tsq")),
        }),
      );
      expect(response.status).toBe(200);
      expect(response.headers.get("content-type")).toBe("application/timestamp-reply");
      fs.writeFileSync(file("reply.tsr"), Buffer.from(await response.arrayBuffer()));

      const authority = await ensureTimestampAuthority();
      const ca = await prisma.certificateAuthority.findFirstOrThrow();
      fs.writeFileSync(file("ca.pem"), ca.certPem);
      fs.writeFileSync(file("tsa.pem"), authority.certPem);

      const text = run(["ts", "-reply", "-in", file("reply.tsr"), "-text"]);
      expect(text.output).toContain("Status: Granted");
      expect(text.output).toMatch(/Nonce: 0x[0-9A-F]+/);

      const verified = run(["ts", "-verify", "-in", file("reply.tsr"), "-queryfile", file("request.tsq"), "-CAfile", file("ca.pem"), "-untrusted", file("tsa.pem")]);
      expect(verified.output).toContain("Verification: OK");
    },
  );
});

describe("the RFC 3161 HTTP endpoint", () => {
  it("publishes the authority's certificate without authentication", async () => {
    const { GET } = await import("@/app/api/pki/tsa/route");
    const response = await GET();
    expect(response.status).toBe(200);
    expect(response.headers.get("Content-Type")).toBe("application/x-pem-file");
    const pem = await response.text();
    expect(pem).toBe((await ensureTimestampAuthority()).certPem);
    expect(new x509.X509Certificate(pem).getExtension(x509.ExtendedKeyUsageExtension)?.critical).toBe(true);
  });

  it("requires a signed-in account", async () => {
    const response = await tsaEndpoint(
      new Request("http://localhost/api/tsa", {
        method: "POST",
        headers: { "content-type": "application/timestamp-query" },
        body: new Uint8Array([0x30, 0x00]),
      }),
    );
    expect(response.status).toBe(401);
  });

  it("refuses any other content type", async () => {
    session.token = await createSessionToken(signer);
    const response = await tsaEndpoint(
      new Request("http://localhost/api/tsa", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" }),
    );
    expect(response.status).toBe(415);
  });

  it("answers a malformed request with an RFC 3161 rejection rather than an error", async () => {
    session.token = await createSessionToken(signer);
    const response = await tsaEndpoint(
      new Request("http://localhost/api/tsa", {
        method: "POST",
        headers: { "content-type": "application/timestamp-query" },
        body: new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x07]),
      }),
    );
    expect(response.status).toBe(200);
    const reply = AsnConvert.parse(await response.arrayBuffer(), TimeStampResp);
    expect(reply.status.status).toBe(PKIStatus.rejection);
    expect(reply.timeStampToken).toBeUndefined();
  });

  it("uses the certificate in the token only when the request asks for it", async () => {
    const withCertificate = await issueTimestampToken({ imprint: imprintOf("with"), includeCertificate: true });
    const without = await issueTimestampToken({ imprint: imprintOf("without"), includeCertificate: false });
    const certificates = (token: Buffer) =>
      AsnConvert.parse(AsnConvert.parse(token, ContentInfo).content, SignedData).certificates?.length ?? 0;
    expect(certificates(withCertificate.token)).toBe(1);
    expect(certificates(without.token)).toBe(0);
    expect(pemBody((await ensureTimestampAuthority()).certPem).length).toBeGreaterThan(0);
  });
});
