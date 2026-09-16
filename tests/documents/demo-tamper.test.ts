import { beforeAll, describe, expect, it } from "vitest";
import { AuthorizationError, type Actor } from "@/lib/auth/rbac";
import { ALGORITHMS, type Algorithm } from "@/lib/crypto/orchestrator";
import { prisma } from "@/lib/db";
import {
  restoreTamper,
  tamperCiphertext,
  tamperContent,
  tamperSignature,
  tamperState,
} from "@/lib/documents/demo-tamper";
import { uploadDocument } from "@/lib/documents/service";
import { signDocument } from "@/lib/documents/signing";
import { readBlob } from "@/lib/documents/storage";
import { verifyDocument } from "@/lib/documents/verification";
import { ensureRootCa } from "@/lib/pki/ca";
import { issueCertificate } from "@/lib/pki/certificates";
import { seedUsers } from "@/prisma/fixtures";
import { resetDatabase } from "@/tests/helpers/db";
import { ensureMasterKey } from "@/tests/helpers/master-key";

const ORIGINAL = Buffer.from("Amount payable: 4,000\n");
const REPLACEMENT = Buffer.from("Amount payable: 9,000\n");

let admin: Actor;
let signer: Actor;
let certificate: Awaited<ReturnType<typeof issueCertificate>>;
let counter = 0;

beforeAll(async () => {
  ensureMasterKey();
  await resetDatabase();
  await seedUsers();
  await ensureRootCa();

  const users = await prisma.user.findMany();
  const id = (email: string) => users.find((user) => user.email === email)!.id;
  admin = { userId: id("admin@demo"), email: "admin@demo", role: "ADMIN" };
  signer = { userId: id("signer@demo"), email: "signer@demo", role: "SIGNER" };

  certificate = await issueCertificate({ actor: admin, algorithm: ALGORITHMS[0] as Algorithm });
}, 120_000);

/** A freshly uploaded and signed document, so each test starts from an untampered one. */
async function signedDocument() {
  counter += 1;
  const document = await uploadDocument({
    actor: admin,
    filename: `tamper-subject-${counter}.txt`,
    mimeType: "text/plain",
    bytes: new Uint8Array(Buffer.concat([ORIGINAL, Buffer.from(String(counter))])),
  });
  await signDocument({ actor: admin, documentId: document.id, certificateId: certificate.id });
  return document;
}

describe("demonstration tampering", () => {
  it("replacing the stored bytes is caught as a hash mismatch, and restore is byte-exact", async () => {
    const document = await signedDocument();
    const before = await readBlob(`documents/${document.id}/v1.bin`);
    expect((await verifyDocument(admin, document.id)).outcome).toBe("VALID");

    const state = await tamperContent(admin, document.id, new Uint8Array(REPLACEMENT));
    expect(state.contentAltered).toBe(true);
    expect(state.storedHash).not.toBe(state.signedHash);

    const tampered = await verifyDocument(admin, document.id);
    expect(tampered.outcome).toBe("INVALID");
    expect(tampered.reason).toBe("HASH_MISMATCH");

    // The replacement really is on disk: this is not a flag the verifier is reading.
    expect(await readBlob(`documents/${document.id}/v1.bin`)).toEqual(REPLACEMENT);

    await restoreTamper(admin, document.id);
    expect(await readBlob(`documents/${document.id}/v1.bin`)).toEqual(before);
    expect((await verifyDocument(admin, document.id)).outcome).toBe("VALID");
  });

  it("flipping a signature bit is caught as an invalid signature, and restore is byte-exact", async () => {
    const document = await signedDocument();
    const version = await prisma.documentVersion.findFirstOrThrow({ where: { documentId: document.id } });
    const before = await prisma.signature.findUniqueOrThrow({ where: { documentVersionId: version.id } });

    await tamperSignature(admin, document.id);

    const after = await prisma.signature.findUniqueOrThrow({ where: { documentVersionId: version.id } });
    expect(Buffer.from(after.signatureBytes)).not.toEqual(Buffer.from(before.signatureBytes));
    // A well-formed signature of the right length, so it can only fail cryptographically.
    expect(after.signatureBytes.length).toBe(before.signatureBytes.length);

    const tampered = await verifyDocument(admin, document.id);
    expect(tampered.outcome).toBe("INVALID");
    expect(tampered.reason).toBe("SIGNATURE_INVALID");

    await restoreTamper(admin, document.id);
    const restored = await prisma.signature.findUniqueOrThrow({ where: { documentVersionId: version.id } });
    expect(Buffer.from(restored.signatureBytes)).toEqual(Buffer.from(before.signatureBytes));
    expect((await verifyDocument(admin, document.id)).outcome).toBe("VALID");
  });

  it("flipping a ciphertext bit makes the blob unreadable, and restore recovers it", async () => {
    const document = await signedDocument();
    const before = await readBlob(`documents/${document.id}/v1.bin`);

    const state = await tamperCiphertext(admin, document.id);
    expect(state.storedHash).toBeNull();
    expect(state.storedHashError).toBeTruthy();

    expect((await verifyDocument(admin, document.id)).outcome).not.toBe("VALID");

    await restoreTamper(admin, document.id);
    expect(await readBlob(`documents/${document.id}/v1.bin`)).toEqual(before);
    expect((await verifyDocument(admin, document.id)).outcome).toBe("VALID");
  });

  it("reports an untampered document as matching", async () => {
    const document = await signedDocument();
    const state = await tamperState(document.id);
    expect(state.contentAltered).toBe(false);
    expect(state.signatureAltered).toBe(false);
    expect(state.storedHash).toBe(state.signedHash);
  });

  it("refuses every action to a role without the capability", async () => {
    const document = await signedDocument();
    await expect(tamperContent(signer, document.id, new Uint8Array(REPLACEMENT))).rejects.toThrow(AuthorizationError);
    await expect(tamperSignature(signer, document.id)).rejects.toThrow(AuthorizationError);
    await expect(tamperCiphertext(signer, document.id)).rejects.toThrow(AuthorizationError);
    await expect(restoreTamper(signer, document.id)).rejects.toThrow(AuthorizationError);
  });

  it("refuses to restore a document that was never altered", async () => {
    const document = await signedDocument();
    await expect(restoreTamper(admin, document.id)).rejects.toThrow(/not been altered/);
  });
});
