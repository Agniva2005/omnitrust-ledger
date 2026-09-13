// Regression: an honest signature intermittently verified as UNVERIFIABLE /
// REVOCATION_STATUS_UNAVAILABLE (seen in tests/verification/algorithm-confusion.test.ts and
// tests/api/routes.test.ts, about one combined run in four).
//
// verifyDocument fixes its evaluation instant `now` at the start. Signing checks revocation from
// the certificate row, so on a fresh installation no CRL exists until verification needs one. The
// time-stamp step checked the Time-Stamp Authority's revocation at the clock time instead of at
// `now`, so it was that step that issued the first CRL, with thisUpdate at the then-current
// second. When a second boundary fell between `now` and that moment, the certificate's own
// revocation step (evaluated at `now`) found a CRL from its future, rejected it as not current,
// and the verdict became UNVERIFIABLE. Verifying at an explicit earlier instant makes the race
// deterministic: every revocation decision in one verification must use the same instant.
import { beforeAll, describe, expect, it } from "vitest";
import type { Actor } from "@/lib/auth/rbac";
import { prisma } from "@/lib/db";
import { uploadDocument } from "@/lib/documents/service";
import { signDocument } from "@/lib/documents/signing";
import { verifyDocument } from "@/lib/documents/verification";
import { ensureRootCa } from "@/lib/pki/ca";
import { issueCertificate } from "@/lib/pki/certificates";
import { CA_ALGORITHM } from "@/lib/pki/policy";
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
  const actorFor = (email: string, role: Actor["role"]): Actor => ({ userId: users.find((user) => user.email === email)!.id, email, role });
  signer = actorFor("signer@demo", "SIGNER");
  verifier = actorFor("verifier@demo", "VERIFIER");
}, 60_000);

describe("the first CRL of an installation, issued during verification", () => {
  it("is judged at the verification instant by every step, so an honest signature stays VALID", async () => {
    const certificate = await issueCertificate({ actor: signer, algorithm: CA_ALGORITHM });
    const document = await uploadDocument({ actor: signer, filename: "crl-instant.txt", mimeType: "text/plain", bytes: Buffer.from("verified at an instant before the first CRL") });
    const signed = await signDocument({ actor: signer, documentId: document.id, certificateId: certificate.id });
    expect(signed.timestamp).not.toBeNull();
    expect(await prisma.revocationList.count()).toBe(0);

    // Let the clock move more than a second past the signing time, then verify at an instant
    // that is still after the proven signing time but a full second before the clock.
    await new Promise((resolve) => setTimeout(resolve, 2_200));
    const at = new Date(Date.now() - 1_100);
    expect(at.getTime()).toBeGreaterThan(signed.timestamp!.genTime.getTime() + 1_000);

    const result = await verifyDocument(verifier, document.id, { at });
    expect(result.steps.filter((step) => step.status !== "PASS" && !step.optional), JSON.stringify(result.steps)).toEqual([]);
    expect(result.outcome).toBe("VALID");
    expect(result.trust.trustedTime).not.toBeNull();

    const crl = await prisma.revocationList.findFirstOrThrow({ orderBy: { crlNumber: "desc" } });
    expect(crl.thisUpdate.getTime()).toBeLessThanOrEqual(at.getTime());
  }, 30_000);
});
