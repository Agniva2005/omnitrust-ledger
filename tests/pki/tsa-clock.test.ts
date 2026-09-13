// Regression: the first time-stamp on a fresh installation must not be issued before its own
// Time-Stamp Authority exists.
//
// Found through an intermittent Security Lab control failure. issueTimestampToken took its
// genTime on entry, then created the authority if there was none. When that creation crossed
// a second boundary, the authority certificate's notBefore (whole seconds) fell one second
// after the token's genTime, and the verifier correctly refused the token as issued outside the
// authority's validity, so a brand-new installation's first signature could carry an invalid
// time-stamp. This test forces the boundary crossing deterministically instead of waiting for it.
import { X509Certificate } from "node:crypto";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { sha256 } from "@/lib/crypto/hash";
import { prisma } from "@/lib/db";
import { ensureRootCa } from "@/lib/pki/ca";
import { issueTimestampToken, verifyTimestampToken } from "@/lib/pki/tsa";
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

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe("time-stamping on a fresh installation", () => {
  it("never dates the first token before the authority certificate it is issued under", async () => {
    // A moment 3 s ahead of now (so the root CA is already valid), 1 ms before a second ends.
    const secondEnd = new Date(Math.ceil((Date.now() + 3000) / 1000) * 1000 - 1);
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(secondEnd);

    // Creating the authority takes real time; make it cross into the next second, as it can.
    const lookup = prisma.timestampAuthority.findFirst.bind(prisma.timestampAuthority);
    vi.spyOn(prisma.timestampAuthority, "findFirst").mockImplementation((async (...args: Parameters<typeof lookup>) => {
      const found = await lookup(...args);
      if (!found) vi.setSystemTime(new Date(secondEnd.getTime() + 5));
      return found;
    }) as typeof prisma.timestampAuthority.findFirst);

    const imprint = sha256("first signature on a fresh installation");
    const issued = await issueTimestampToken({ imprint });
    const authority = await prisma.timestampAuthority.findFirstOrThrow({ where: { id: issued.authorityId } });
    const verification = await verifyTimestampToken(issued.token, imprint);

    // The row's createdAt is set by the database engine on the real clock, so compare with the
    // authority certificate itself, whose validity was taken from the (faked) application clock.
    const notBefore = new Date(new X509Certificate(authority.certPem).validFrom);
    // The boundary crossing really was forced: the authority certificate starts in the next second.
    expect(notBefore.getTime()).toBeGreaterThan(secondEnd.getTime());
    expect(issued.genTime.getTime(), `token genTime ${issued.genTime.toISOString()}, authority notBefore ${notBefore.toISOString()}`).toBeGreaterThanOrEqual(notBefore.getTime());
    expect(verification.status, verification.explanation).toBe("VALID");
  });
});
