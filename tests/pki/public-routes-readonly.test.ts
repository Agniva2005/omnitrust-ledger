// Security audit finding: two unauthenticated GET routes changed server state. GET /api/pki/tsa
// created the Time-Stamp Authority (a key generation and database writes) and GET /api/pki/crl
// made the CA sign a new list whenever the stored one had lapsed. GET requests are exempt from
// the cross-site check and need no session, so anyone could trigger both. They are now
// read-only; issuance stays with revocation and authenticated verification.
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { GET as getCrl } from "@/app/api/pki/crl/route";
import { GET as getTsaCertificate } from "@/app/api/pki/tsa/route";
import { prisma } from "@/lib/db";
import { ensureRootCa } from "@/lib/pki/ca";
import { issueCrl } from "@/lib/pki/crl";
import { ensureTimestampAuthority } from "@/lib/pki/tsa";
import { resetDatabase } from "@/tests/helpers/db";
import { ensureMasterKey } from "@/tests/helpers/master-key";

beforeAll(async () => {
  ensureMasterKey();
  await resetDatabase();
  await ensureRootCa();
}, 60_000);

beforeEach(async () => {
  await prisma.revocationList.deleteMany();
  await prisma.timestampAuthority.deleteMany();
});

const auditCount = (action: string) => prisma.auditLogEntry.count({ where: { action } });

describe("GET /api/pki/tsa", () => {
  it("returns 404 and creates nothing when no authority exists", async () => {
    const auditsBefore = await auditCount("TSA_CREATED");
    const response = await getTsaCertificate();

    expect(response.status).toBe(404);
    expect(await prisma.timestampAuthority.count()).toBe(0);
    expect(await auditCount("TSA_CREATED")).toBe(auditsBefore);
  });

  it("serves the existing authority's certificate without creating another", async () => {
    const authority = await ensureTimestampAuthority();
    const response = await getTsaCertificate();

    expect(response.status).toBe(200);
    expect(await response.text()).toBe(authority.certPem);
    expect(await prisma.timestampAuthority.count()).toBe(1);
  });
});

describe("GET /api/pki/crl", () => {
  it("returns 404 and makes the CA sign nothing when no list exists", async () => {
    const auditsBefore = await auditCount("CRL_ISSUED");
    const response = await getCrl(new Request("http://localhost/api/pki/crl"));

    expect(response.status).toBe(404);
    expect(await prisma.revocationList.count()).toBe(0);
    expect(await auditCount("CRL_ISSUED")).toBe(auditsBefore);
  });

  it("serves a lapsed list as stored, marked by its next-update time, instead of issuing a new one", async () => {
    const lapsed = await issueCrl({ at: new Date(Date.now() - 30 * 86_400_000) });
    expect(lapsed.nextUpdate.getTime()).toBeLessThan(Date.now());
    const auditsBefore = await auditCount("CRL_ISSUED");

    const response = await getCrl(new Request("http://localhost/api/pki/crl"));

    expect(response.status).toBe(200);
    expect(Buffer.from(await response.arrayBuffer()).equals(Buffer.from(lapsed.der))).toBe(true);
    expect(response.headers.get("X-CRL-Next-Update")).toBe(lapsed.nextUpdate.toISOString());
    expect(await prisma.revocationList.count()).toBe(1);
    expect(await auditCount("CRL_ISSUED")).toBe(auditsBefore);
  });
});
