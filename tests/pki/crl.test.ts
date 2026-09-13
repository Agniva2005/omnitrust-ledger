// Certificate revocation lists: the signed evidence verification reads revocation status
// from. A list the CA did not sign, that has been altered, that has lapsed, or that is not
// a CRL at all must make status unavailable, never "not revoked". Where an OpenSSL binary
// is available, the exported list is also checked by an independent implementation.
import { spawnSync } from "node:child_process";
import { webcrypto } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import * as x509 from "@peculiar/x509";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { GET as getCaCertificate } from "@/app/api/pki/ca/route";
import { GET as getCrl } from "@/app/api/pki/crl/route";
import type { Actor } from "@/lib/auth/rbac";
import { prisma } from "@/lib/db";
import { caCertificate, ensureRootCa, getRootCa } from "@/lib/pki/ca";
import { issueCertificate, revokeCertificate } from "@/lib/pki/certificates";
import {
  RevocationStatusUnavailableError,
  authenticateCrl,
  crlPem,
  currentCrl,
  issueCrl,
  normaliseSerial,
  revocationStatus,
} from "@/lib/pki/crl";
import { seedUsers } from "@/prisma/fixtures";
import { resetDatabase } from "@/tests/helpers/db";
import { ensureMasterKey } from "@/tests/helpers/master-key";

let admin: Actor;
let signer: Actor;

const OPENSSL_AVAILABLE = spawnSync("openssl", ["version"]).status === 0;
const INTEROP_DIR = path.join(process.cwd(), "storage", "test", "openssl-crl");

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
  admin = actorFor("admin@demo", "ADMIN");
  signer = actorFor("signer@demo", "SIGNER");
}, 60_000);

beforeEach(async () => {
  await prisma.revocationList.deleteMany();
  await prisma.certificate.deleteMany();
  await prisma.keyPair.deleteMany();
});

/** A certificate valid from an hour ago, so an invalidity date in the recent past is legal. */
function issue() {
  return issueCertificate({
    actor: signer,
    algorithm: "ECDSA_P256",
    notBefore: new Date(Date.now() - 3_600_000),
    notAfter: new Date(Date.now() + 86_400_000),
  });
}

async function latestAuthenticated() {
  const list = await prisma.revocationList.findFirstOrThrow({ orderBy: { crlNumber: "desc" } });
  return { list, crl: await authenticateCrl(list.der) };
}

describe("issuing", () => {
  it("issues a signed, numbered CRL on every revocation, carrying reason codes and invalidity dates", async () => {
    const compromised = await issue();
    const replaced = await issue();
    const invalidFrom = new Date(Date.now() - 600_000);

    await revokeCertificate({
      actor: admin,
      certificateId: compromised.id,
      reason: "keyCompromise",
      invalidityDate: invalidFrom,
    });
    await revokeCertificate({ actor: admin, certificateId: replaced.id, reason: "superseded" });

    const lists = await prisma.revocationList.findMany({ orderBy: { crlNumber: "asc" } });
    expect(lists.map((list) => list.crlNumber)).toEqual([1, 2]);

    const { crl } = await latestAuthenticated();
    expect(crl.crlNumber).toBe(2);
    expect(crl.entries).toHaveLength(2);

    const compromisedEntry = crl.entries.find(
      (entry) => entry.serialNumber === normaliseSerial(compromised.serialNumber),
    );
    expect(compromisedEntry?.reason).toBe("keyCompromise");
    expect(compromisedEntry?.invalidityDate?.getTime()).toBe(
      Math.floor(invalidFrom.getTime() / 1000) * 1000,
    );

    const replacedEntry = crl.entries.find(
      (entry) => entry.serialNumber === normaliseSerial(replaced.serialNumber),
    );
    expect(replacedEntry?.reason).toBe("superseded");
    expect(replacedEntry?.invalidityDate).toBeNull();
  });

  it("omits the reason extension for unspecified, as RFC 5280 asks, and reads that back as unspecified", async () => {
    const certificate = await issue();
    await revokeCertificate({ actor: admin, certificateId: certificate.id });

    const { list, crl } = await latestAuthenticated();
    expect(new x509.X509Crl(new Uint8Array(list.der)).entries[0].reason).toBeUndefined();
    expect(crl.entries[0].reason).toBe("unspecified");
  });

  it("refuses an invalidity date later than the revocation, or before the certificate was valid", async () => {
    const certificate = await issue();
    await expect(
      revokeCertificate({
        actor: admin,
        certificateId: certificate.id,
        reason: "keyCompromise",
        invalidityDate: new Date(Date.now() + 60_000),
      }),
    ).rejects.toThrow(/later than the revocation/);
    await expect(
      revokeCertificate({
        actor: admin,
        certificateId: certificate.id,
        reason: "keyCompromise",
        invalidityDate: new Date("2000-01-01T00:00:00Z"),
      }),
    ).rejects.toThrow(/precede the certificate/);
  });

  it("reports revocation status from the authenticated list", async () => {
    const revoked = await issue();
    const active = await issue();
    await revokeCertificate({ actor: admin, certificateId: revoked.id, reason: "cessationOfOperation" });

    const revokedStatus = await revocationStatus(revoked.serialNumber);
    expect(revokedStatus.revocation?.reason).toBe("cessationOfOperation");
    expect((await revocationStatus(active.serialNumber)).revocation).toBeNull();
  });

  it("issues a fresh list when none exists, and again when the newest has lapsed", async () => {
    const first = await currentCrl();
    expect(first.crlNumber).toBe(1);

    const afterExpiry = new Date(first.nextUpdate.getTime() + 1000);
    const second = await currentCrl(afterExpiry);
    expect(second.crlNumber).toBe(2);
    expect((await authenticateCrl(second.der, afterExpiry)).crlNumber).toBe(2);
  });
});

describe("refusing untrustworthy revocation evidence", () => {
  it("refuses a list whose signature has been altered", async () => {
    const list = await issueCrl();
    const altered = Buffer.from(list.der);
    altered[altered.length - 1] ^= 0x01;
    await expect(authenticateCrl(altered)).rejects.toThrow(RevocationStatusUnavailableError);
  });

  it("refuses a list carrying the CA's name but signed by a different key", async () => {
    const ca = await getRootCa();
    const impostor = await webcrypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"],
    );
    const forged = await x509.X509CrlGenerator.create({
      issuer: caCertificate(ca).subject,
      thisUpdate: new Date(Date.now() - 1000),
      nextUpdate: new Date(Date.now() + 86_400_000),
      entries: [],
      signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
      signingKey: impostor.privateKey,
    });
    await expect(authenticateCrl(new Uint8Array(forged.rawData))).rejects.toThrow(
      /signature does not verify/,
    );
  });

  it("refuses a list that is no longer current", async () => {
    const list = await issueCrl();
    await expect(
      authenticateCrl(list.der, new Date(list.nextUpdate.getTime() + 1000)),
    ).rejects.toThrow(/not current/);
  });

  it("refuses bytes that are not a CRL", async () => {
    await expect(authenticateCrl(new Uint8Array([1, 2, 3]))).rejects.toThrow(/malformed/);
  });
});

describe("export", () => {
  it("armours PEM with the RFC 7468 label OpenSSL requires", async () => {
    const list = await issueCrl();
    expect(crlPem(list)).toMatch(/^-----BEGIN X509 CRL-----\n/);
  });

  it("serves the current CRL as DER and the CA certificate as PEM, without authentication", async () => {
    const crlResponse = await getCrl(new Request("http://localhost/api/pki/crl"));
    expect(crlResponse.status).toBe(200);
    expect(crlResponse.headers.get("Content-Type")).toBe("application/pkix-crl");
    const der = new Uint8Array(await crlResponse.arrayBuffer());
    expect((await authenticateCrl(der)).crlNumber).toBeGreaterThan(0);

    const caResponse = await getCaCertificate();
    expect(caResponse.status).toBe(200);
    expect(await caResponse.text()).toContain("-----BEGIN CERTIFICATE-----");
  });

  it.runIf(OPENSSL_AVAILABLE)(
    "is independently accepted by OpenSSL, which also rejects the revoked certificate and accepts the active one",
    async () => {
      const revoked = await issue();
      const active = await issue();
      await revokeCertificate({
        actor: admin,
        certificateId: revoked.id,
        reason: "keyCompromise",
        invalidityDate: new Date(Date.now() - 600_000),
      });

      fs.mkdirSync(INTEROP_DIR, { recursive: true });
      const file = (name: string) => path.join(INTEROP_DIR, name);
      const ca = await getRootCa();
      fs.writeFileSync(file("ca.pem"), ca.certPem);
      fs.writeFileSync(file("crl.pem"), crlPem(await currentCrl()));
      fs.writeFileSync(file("revoked.pem"), revoked.certPem);
      fs.writeFileSync(file("active.pem"), active.certPem);

      const run = (args: string[]) => {
        const result = spawnSync("openssl", args, { encoding: "utf8" });
        return { status: result.status, output: `${result.stdout}\n${result.stderr}` };
      };

      const listing = run(["crl", "-in", file("crl.pem"), "-noout", "-text", "-CAfile", file("ca.pem")]);
      expect(listing.status).toBe(0);
      expect(listing.output).toContain("verify OK");
      expect(listing.output).toContain("Key Compromise");
      expect(listing.output).toContain("Invalidity Date");
      expect(listing.output).toContain("CRL Number");

      const verifyActive = run(["verify", "-crl_check", "-CAfile", file("ca.pem"), "-CRLfile", file("crl.pem"), file("active.pem")]);
      expect(verifyActive.status).toBe(0);

      const verifyRevoked = run(["verify", "-crl_check", "-CAfile", file("ca.pem"), "-CRLfile", file("crl.pem"), file("revoked.pem")]);
      expect(verifyRevoked.status).not.toBe(0);
      expect(verifyRevoked.output).toContain("certificate revoked");
    },
  );
});

describe("serial number encoding (regression)", () => {
  // Found over real HTTP: about half of random serials have their first byte's top bit
  // set, and the CRL encoded those as negative INTEGERs that no longer matched the
  // certificate, so OpenSSL reported the revoked certificate as valid. These tests force
  // that case rather than relying on a lucky serial.
  async function issueWithTopBitSerial() {
    for (let attempt = 0; attempt < 40; attempt += 1) {
      const certificate = await issue();
      if (Number.parseInt(certificate.serialNumber.slice(0, 2), 16) >= 0x80) return certificate;
      await prisma.certificate.delete({ where: { id: certificate.id } });
    }
    throw new Error("no top-bit serial in 40 attempts");
  }

  it("encodes the CRL entry serial as the same positive INTEGER the certificate carries", async () => {
    const { AsnConvert } = await import("@peculiar/asn1-schema");
    const { Certificate, CertificateList } = await import("@peculiar/asn1-x509");
    const { pemBody } = await import("@/lib/crypto/pem");

    const certificate = await issueWithTopBitSerial();
    await revokeCertificate({ actor: admin, certificateId: certificate.id, reason: "superseded" });

    const list = await prisma.revocationList.findFirstOrThrow({ orderBy: { crlNumber: "desc" } });
    const crl = AsnConvert.parse(list.der, CertificateList);
    const entrySerial = Buffer.from(crl.tbsCertList.revokedCertificates![0].userCertificate);
    const certificateSerial = Buffer.from(
      AsnConvert.parse(pemBody(certificate.certPem), Certificate).tbsCertificate.serialNumber,
    );

    expect(entrySerial[0] & 0x80).toBe(0);
    expect(entrySerial.equals(certificateSerial)).toBe(true);
  });

  it.runIf(OPENSSL_AVAILABLE)(
    "lets OpenSSL match a top-bit serial and report that certificate revoked",
    async () => {
      const certificate = await issueWithTopBitSerial();
      await revokeCertificate({ actor: admin, certificateId: certificate.id, reason: "keyCompromise" });

      fs.mkdirSync(INTEROP_DIR, { recursive: true });
      const file = (name: string) => path.join(INTEROP_DIR, name);
      fs.writeFileSync(file("ca-topbit.pem"), (await getRootCa()).certPem);
      fs.writeFileSync(file("crl-topbit.pem"), crlPem(await currentCrl()));
      fs.writeFileSync(file("revoked-topbit.pem"), certificate.certPem);

      const result = spawnSync(
        "openssl",
        ["verify", "-crl_check", "-CAfile", file("ca-topbit.pem"), "-CRLfile", file("crl-topbit.pem"), file("revoked-topbit.pem")],
        { encoding: "utf8" },
      );
      expect(result.status).not.toBe(0);
      expect(`${result.stdout}${result.stderr}`).toContain("certificate revoked");

      const listing = spawnSync("openssl", ["crl", "-in", file("crl-topbit.pem"), "-noout", "-text"], {
        encoding: "utf8",
      });
      expect(listing.stdout).toContain(`Serial Number: ${certificate.serialNumber.toUpperCase()}`);
      expect(listing.stdout).not.toMatch(/Serial Number: -/);
    },
  );

  it("keeps positive serials unchanged and adds exactly one zero byte to top-bit ones", async () => {
    const { positiveSerialHex } = await import("@/lib/pki/crl");
    expect(positiveSerialHex("3D93")).toBe("3D93");
    expect(positiveSerialHex("C26C")).toBe("00C26C");
    expect(positiveSerialHex("ABC")).toBe("0ABC");
  });
});
