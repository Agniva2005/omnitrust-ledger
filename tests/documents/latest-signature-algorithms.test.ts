// The documents list shows which algorithm signed each document; the query behind it must report
// the newest signature per document and leave unsigned documents out rather than inventing a value.
import { beforeAll, describe, expect, it } from "vitest";
import type { Actor } from "@/lib/auth/rbac";
import { prisma } from "@/lib/db";
import { uploadDocument } from "@/lib/documents/service";
import { latestSignatureAlgorithms, signDocument } from "@/lib/documents/signing";
import { ensureRootCa } from "@/lib/pki/ca";
import { issueCertificate } from "@/lib/pki/certificates";
import { CA_ALGORITHM } from "@/lib/pki/policy";
import { seedUsers } from "@/prisma/fixtures";
import { resetDatabase } from "@/tests/helpers/db";
import { ensureMasterKey } from "@/tests/helpers/master-key";

let signer: Actor;

beforeAll(async () => {
  ensureMasterKey();
  await resetDatabase();
  await seedUsers();
  await ensureRootCa();
  const user = await prisma.user.findUniqueOrThrow({ where: { email: "signer@demo" } });
  signer = { userId: user.id, email: user.email, role: "SIGNER" };
}, 60_000);

describe("latestSignatureAlgorithms", () => {
  it("maps signed documents to the algorithm of their newest signature and omits unsigned ones", async () => {
    const certificate = await issueCertificate({ actor: signer, algorithm: CA_ALGORITHM });
    const signed = await uploadDocument({ actor: signer, filename: "listed-signed.txt", mimeType: "text/plain", bytes: Buffer.from("signed for the list") });
    const unsigned = await uploadDocument({ actor: signer, filename: "listed-unsigned.txt", mimeType: "text/plain", bytes: Buffer.from("never signed") });
    await signDocument({ actor: signer, documentId: signed.id, certificateId: certificate.id });

    const latest = await latestSignatureAlgorithms([signed.id, unsigned.id]);
    expect(latest.get(signed.id)).toBe(CA_ALGORITHM);
    expect(latest.has(unsigned.id)).toBe(false);
  });

  it("returns an empty map for no documents without querying", async () => {
    expect((await latestSignatureAlgorithms([])).size).toBe(0);
  });
});
