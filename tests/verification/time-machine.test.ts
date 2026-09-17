// Verifying as at another instant.
//
// The headline is that the verdict moves with the question: the same bytes, signature and
// certificate give different answers before and after a revocation, and which answer depends on
// the reason given. The invariant underneath it matters just as much — asking a hypothetical
// question must not publish a revocation list, because a future-dated list becomes the newest
// one and then nothing verifies at any earlier time. That is a real failure this test exists to
// prevent; it happened.
import { beforeAll, describe, expect, it } from "vitest";
import { type Actor } from "@/lib/auth/rbac";
import { ALGORITHMS, type Algorithm } from "@/lib/crypto/orchestrator";
import { prisma } from "@/lib/db";
import { uploadDocument } from "@/lib/documents/service";
import { signDocument } from "@/lib/documents/signing";
import { verificationMoments } from "@/lib/documents/timeline";
import { verifyDocument } from "@/lib/documents/verification";
import { ensureRootCa } from "@/lib/pki/ca";
import { issueCertificate, revokeCertificate } from "@/lib/pki/certificates";
import { ensureTimestampAuthority } from "@/lib/pki/tsa";
import { seedUsers } from "@/prisma/fixtures";
import { resetDatabase } from "@/tests/helpers/db";
import { ensureMasterKey } from "@/tests/helpers/master-key";

const SECOND = 1000;

let admin: Actor;
let counter = 0;

beforeAll(async () => {
  ensureMasterKey();
  await resetDatabase();
  await seedUsers();
  await ensureRootCa();
  // Without a Time-Stamp Authority nothing proves when a signature existed, and the
  // reason-dependent revocation behaviour this file is about cannot arise at all.
  await ensureTimestampAuthority();

  const users = await prisma.user.findMany();
  admin = { userId: users.find((user) => user.email === "admin@demo")!.id, email: "admin@demo", role: "ADMIN" };
}, 120_000);

/** A signed document under its own certificate, so revoking it affects nothing else. */
async function signedUnderOwnCertificate() {
  counter += 1;
  const certificate = await issueCertificate({ actor: admin, algorithm: ALGORITHMS[0] as Algorithm });
  const document = await uploadDocument({
    actor: admin,
    filename: `time-machine-${counter}.txt`,
    mimeType: "text/plain",
    bytes: new Uint8Array(Buffer.from(`subject ${counter}`)),
  });
  await signDocument({ actor: admin, documentId: document.id, certificateId: certificate.id });
  return { document, certificate };
}

describe("verifying as at another instant", () => {
  it("never publishes a revocation list, whatever instant is asked about", async () => {
    const { document } = await signedUnderOwnCertificate();
    const before = await prisma.revocationList.count();
    const newest = await prisma.revocationList.findFirst({ orderBy: { crlNumber: "desc" } });

    for (const at of [new Date("2020-01-01T00:00:00Z"), new Date("2030-01-01T00:00:00Z"), new Date("2099-01-01T00:00:00Z")]) {
      await verifyDocument(admin, document.id, { at, issueCrlIfStale: false });
    }

    expect(await prisma.revocationList.count(), "a hypothetical question published a CRL").toBe(before);
    const after = await prisma.revocationList.findFirst({ orderBy: { crlNumber: "desc" } });
    expect(after?.crlNumber).toBe(newest?.crlNumber);
  }, 60_000);

  it("keeps the present verifiable after asking about the far future", async () => {
    const { document } = await signedUnderOwnCertificate();
    expect((await verifyDocument(admin, document.id)).outcome).toBe("VALID");

    await verifyDocument(admin, document.id, { at: new Date("2099-01-01T00:00:00Z"), issueCrlIfStale: false });

    // The regression: a future-dated list used to become the newest and break every later check.
    expect((await verifyDocument(admin, document.id)).outcome, "asking about the future broke the present").toBe("VALID");
  }, 60_000);

  it("reports unknown revocation beyond the newest list rather than guessing", async () => {
    const { document } = await signedUnderOwnCertificate();
    const newest = await prisma.revocationList.findFirstOrThrow({ orderBy: { crlNumber: "desc" } });

    const beyond = await verifyDocument(admin, document.id, { at: new Date(newest.nextUpdate.getTime() + SECOND), issueCrlIfStale: false });
    expect(beyond.outcome).toBe("UNVERIFIABLE");
    expect(beyond.reason).toBe("REVOCATION_STATUS_UNAVAILABLE");
  }, 60_000);

  it("changes its answer across a keyCompromise revocation with no invalidity date", async () => {
    const { document, certificate } = await signedUnderOwnCertificate();

    // Issuing, signing and revoking inside one second would put "a second before revocation"
    // before the certificate existed, which is a different refusal than the one under test.
    await new Promise((resolve) => setTimeout(resolve, 2500));
    await revokeCertificate({ actor: admin, certificateId: certificate.id, reason: "keyCompromise", comment: "test" });
    const revokedAt = (await prisma.certificate.findUniqueOrThrow({ where: { id: certificate.id } })).revokedAt!;

    const before = await verifyDocument(admin, document.id, { at: new Date(revokedAt.getTime() - SECOND), issueCrlIfStale: false });
    expect(before.outcome).toBe("VALID");

    const after = await verifyDocument(admin, document.id, { at: new Date(revokedAt.getTime() + SECOND), issueCrlIfStale: false });
    expect(after.outcome).toBe("INVALID");
    expect(after.reason).toBe("CERTIFICATE_REVOKED");
    expect(after.trust.revocationDecision).toBe("COMPROMISE_TIME_UNKNOWN");
  }, 60_000);

  it("keeps its answer across an affiliationChanged revocation, which is the whole point", async () => {
    const { document, certificate } = await signedUnderOwnCertificate();

    // The time-stamp proves existence only within the authority's accuracy, ±1 s here. Revoking
    // in the same instant leaves the two intervals overlapping, and the verifier then refuses to
    // say the signature came first — correctly. Separating them is what the demonstration does.
    await new Promise((resolve) => setTimeout(resolve, 2500));
    await revokeCertificate({ actor: admin, certificateId: certificate.id, reason: "affiliationChanged", comment: "test" });
    const revokedAt = (await prisma.certificate.findUniqueOrThrow({ where: { id: certificate.id } })).revokedAt!;

    const after = await verifyDocument(admin, document.id, { at: new Date(revokedAt.getTime() + SECOND), issueCrlIfStale: false });
    // Same mechanism, same moment, opposite answer to the case above — decided by the reason.
    expect(after.outcome).toBe("VALID");
    expect(after.trust.revocationDecision).toBe("SIGNED_BEFORE_REVOCATION");
  }, 60_000);

  it("offers moments drawn from the record, including both sides of a revocation", async () => {
    const { document, certificate } = await signedUnderOwnCertificate();
    await revokeCertificate({ actor: admin, certificateId: certificate.id, reason: "keyCompromise", comment: "test" });

    const moments = await verificationMoments(document.id);
    const ids = moments.map((moment) => moment.id);
    expect(ids).toContain("signed");
    expect(ids).toContain("before-revocation");
    expect(ids).toContain("after-revocation");
    expect(ids).toContain("now");

    // Oldest first, so the row reads as a timeline, and no instant repeats.
    const times = moments.map((moment) => moment.at);
    expect([...times].sort()).toEqual(times);
    expect(new Set(times).size).toBe(times.length);
  }, 60_000);

  it("returns no moments for a version that was never signed", async () => {
    counter += 1;
    const document = await uploadDocument({
      actor: admin,
      filename: `unsigned-${counter}.txt`,
      mimeType: "text/plain",
      bytes: new Uint8Array(Buffer.from(`unsigned ${counter}`)),
    });
    expect(await verificationMoments(document.id)).toEqual([]);
  }, 60_000);
});
