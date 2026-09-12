import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { BadRequestError, ConflictError } from "@/lib/api";
import { AuthorizationError, type Actor } from "@/lib/auth/rbac";
import { sha256Hex } from "@/lib/crypto/hash";
import {
  addDocumentVersion,
  getDocument,
  latestVersion,
  recomputeVersionHash,
  uploadDocument,
} from "@/lib/documents/service";
import { prisma } from "@/lib/db";
import { seedUsers } from "@/prisma/fixtures";
import { resetDatabase } from "@/tests/helpers/db";
import { ensureMasterKey } from "@/tests/helpers/master-key";

let signer: Actor;
let viewer: Actor;

beforeAll(async () => {
  ensureMasterKey();
  await resetDatabase();
  await seedUsers();

  const signerUser = await prisma.user.findUniqueOrThrow({ where: { email: "signer@demo" } });
  const viewerUser = await prisma.user.findUniqueOrThrow({ where: { email: "viewer@demo" } });
  signer = { userId: signerUser.id, email: signerUser.email, role: "SIGNER" };
  viewer = { userId: viewerUser.id, email: viewerUser.email, role: "VIEWER" };
});

beforeEach(async () => {
  await prisma.documentVersion.deleteMany();
  await prisma.document.deleteMany();
});

function upload(bytes: string, filename = "contract.txt") {
  return uploadDocument({
    actor: signer,
    filename,
    mimeType: "text/plain",
    bytes: Buffer.from(bytes),
  });
}

describe("upload", () => {
  it("stores the real SHA-256 of the uploaded bytes and lands in HASHED", async () => {
    const contents = "This agreement is made on the 12th of September.";
    const document = await upload(contents);

    expect(document.currentHash).toBe(sha256Hex(Buffer.from(contents)));
    expect(document.status).toBe("HASHED");
    expect(document.storagePath).toBe(`documents/${document.id}/v1.bin`);
  });

  it("creates version 1 whose hash matches a recomputation from the stored bytes", async () => {
    const document = await upload("version one contents");
    const version = await latestVersion(document.id);

    expect(version.versionNumber).toBe(1);
    expect(await recomputeVersionHash(version)).toBe(version.hash);
    expect(version.hash).toBe(document.currentHash);
  });

  it("matches the published SHA-256 test vector for the uploaded bytes", async () => {
    // FIPS 180-4 / NIST example: SHA-256("abc"). An independently known-correct
    // value, so this cannot pass by being self-consistent with our own hashing.
    const document = await upload("abc", "abc.txt");
    expect(document.currentHash).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  it("hashes raw bytes, including non-UTF8 ones", async () => {
    const bytes = Buffer.from([0x00, 0x01, 0xff, 0x7f, 0x80]);
    const document = await uploadDocument({
      actor: signer,
      filename: "binary.bin",
      mimeType: "application/octet-stream",
      bytes,
    });
    expect(document.currentHash).toBe(sha256Hex(bytes));
    expect(document.currentHash).toHaveLength(64);
  });
});

describe("Section 6 rejection cases", () => {
  it("rejects a zero-byte file", async () => {
    await expect(upload("")).rejects.toThrow(BadRequestError);
    await expect(upload("")).rejects.toThrow(/zero-byte/);
  });

  it("rejects a duplicate upload of identical bytes and names the existing document", async () => {
    const first = await upload("identical contents", "first.txt");
    await expect(upload("identical contents", "second.txt")).rejects.toThrow(ConflictError);
    await expect(upload("identical contents", "second.txt")).rejects.toThrow(
      new RegExp(first.id),
    );
  });

  it("allows the same bytes to be uploaded by a different owner", async () => {
    await upload("shared contents");
    const admin = await prisma.user.findUniqueOrThrow({ where: { email: "admin@demo" } });
    await expect(
      uploadDocument({
        actor: { userId: admin.id, email: admin.email, role: "ADMIN" },
        filename: "same.txt",
        mimeType: "text/plain",
        bytes: Buffer.from("shared contents"),
      }),
    ).resolves.toBeTruthy();
  });

  it("refuses an over-size upload", async () => {
    await expect(
      uploadDocument({
        actor: signer,
        filename: "big.bin",
        mimeType: "application/octet-stream",
        bytes: Buffer.alloc(11 * 1024 * 1024, 1),
      }),
    ).rejects.toThrow(/demo limit/);
  });

  it("refuses a VIEWER (Section 6: a VIEWER cannot upload)", async () => {
    await expect(
      uploadDocument({
        actor: viewer,
        filename: "nope.txt",
        mimeType: "text/plain",
        bytes: Buffer.from("nope"),
      }),
    ).rejects.toThrow(AuthorizationError);
  });
});

describe("versioning", () => {
  it("adds version 2 and returns the document to HASHED with the new hash", async () => {
    const document = await upload("first revision");
    const updated = await addDocumentVersion(
      signer,
      document.id,
      "contract.txt",
      Buffer.from("second revision"),
    );

    expect(updated.status).toBe("HASHED");
    expect(updated.currentHash).toBe(sha256Hex(Buffer.from("second revision")));

    const versions = (await getDocument(signer, document.id)).versions;
    expect(versions.map((version) => version.versionNumber)).toEqual([2, 1]);
    expect(versions[1].hash).toBe(sha256Hex(Buffer.from("first revision")));
  });

  it("keeps each version's own bytes retrievable and correctly hashed", async () => {
    const document = await upload("alpha");
    await addDocumentVersion(signer, document.id, "contract.txt", Buffer.from("beta"));

    for (const version of (await getDocument(signer, document.id)).versions) {
      expect(await recomputeVersionHash(version)).toBe(version.hash);
    }
  });

  it("refuses a new version identical to the current one", async () => {
    const document = await upload("unchanged");
    await expect(
      addDocumentVersion(signer, document.id, "contract.txt", Buffer.from("unchanged")),
    ).rejects.toThrow(/identical/);
  });

  it("refuses a version on someone else's document", async () => {
    const document = await upload("mine");
    const verifier = await prisma.user.findUniqueOrThrow({ where: { email: "verifier@demo" } });
    await expect(
      addDocumentVersion(
        { userId: verifier.id, email: verifier.email, role: "SIGNER" },
        document.id,
        "contract.txt",
        Buffer.from("theirs"),
      ),
    ).rejects.toThrow(/owner or an ADMIN/);
  });
});
