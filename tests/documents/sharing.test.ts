// Consent-based sharing: the only surface here that serves a document to someone with no
// account, so the tests are about what a link may not do as much as what it may.
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { appendAuditEntry } from "@/lib/audit/log";
import { AuthorizationError, type Actor } from "@/lib/auth/rbac";
import { sha256Hex } from "@/lib/crypto/hash";
import { ALGORITHMS, type Algorithm } from "@/lib/crypto/orchestrator";
import { prisma } from "@/lib/db";
import { uploadDocument } from "@/lib/documents/service";
import { ShareUnavailableError, createShare, listShares, openShare, revokeShare } from "@/lib/documents/sharing";
import { signDocument } from "@/lib/documents/signing";
import { ensureRootCa } from "@/lib/pki/ca";
import { issueCertificate } from "@/lib/pki/certificates";
import { seedUsers } from "@/prisma/fixtures";
import { resetDatabase } from "@/tests/helpers/db";
import { ensureMasterKey } from "@/tests/helpers/master-key";

let owner: Actor;
let other: Actor;
let viewer: Actor;
let certificateId: string;
let counter = 0;

beforeAll(() => {
  ensureMasterKey();
});

beforeEach(async () => {
  await resetDatabase();
  await seedUsers();
  await ensureRootCa();

  const users = await prisma.user.findMany();
  const id = (email: string) => users.find((user) => user.email === email)!.id;
  owner = { userId: id("signer@demo"), email: "signer@demo", role: "SIGNER" };
  other = { userId: id("admin@demo"), email: "admin@demo", role: "ADMIN" };
  viewer = { userId: id("viewer@demo"), email: "viewer@demo", role: "VIEWER" };

  certificateId = (await issueCertificate({ actor: owner, algorithm: ALGORITHMS[0] as Algorithm })).id;
});

async function signedDocument() {
  counter += 1;
  const document = await uploadDocument({
    actor: owner,
    filename: `shared-${counter}.txt`,
    mimeType: "text/plain",
    bytes: new Uint8Array(Buffer.from(`shared body ${counter}`)),
  });
  await signDocument({ actor: owner, documentId: document.id, certificateId });
  return document;
}

async function unsignedDocument() {
  counter += 1;
  return uploadDocument({
    actor: owner,
    filename: `unsigned-${counter}.txt`,
    mimeType: "text/plain",
    bytes: new Uint8Array(Buffer.from(`unsigned body ${counter}`)),
  });
}

describe("sharing a document for verification", () => {
  it("stores only a hash of the token, so a copy of the table opens nothing", async () => {
    const document = await signedDocument();
    const { token } = await createShare(owner, document.id, { audience: "Acme Ltd" });

    const rows = await prisma.documentShare.findMany();
    expect(rows).toHaveLength(1);
    // The token itself must appear nowhere in the row.
    expect(JSON.stringify(rows[0])).not.toContain(token);
    expect(rows[0].tokenHash).toBe(sha256Hex(Buffer.from(token, "utf8")));
  });

  it("never writes the token to the audit log either", async () => {
    const document = await signedDocument();
    const { token } = await createShare(owner, document.id, { audience: "Acme Ltd" });

    const entries = await prisma.auditLogEntry.findMany({ where: { action: "DOCUMENT_SHARED" } });
    expect(entries).toHaveLength(1);
    expect(entries[0].metadataJson).not.toContain(token);
  });

  it("opens for a visitor with no account, and records the access without inventing a user", async () => {
    const document = await signedDocument();
    const { token } = await createShare(owner, document.id, { audience: "Acme Ltd", note: "as requested" });

    const opened = await openShare(token);
    expect(opened.documentId).toBe(document.id);
    expect(opened.audience).toBe("Acme Ltd");
    expect(opened.note).toBe("as requested");
    expect(opened.accessCount).toBe(1);

    const access = await prisma.auditLogEntry.findFirstOrThrow({ where: { action: "DOCUMENT_SHARE_ACCESSED" } });
    // The visitor has no account, and the log must not imply one.
    expect(access.actorUserId).toBeNull();

    expect((await openShare(token)).accessCount).toBe(2);
  });

  it("refuses an unknown token, and says nothing about whether one ever existed", async () => {
    await expect(openShare("not-a-real-token")).rejects.toThrow(ShareUnavailableError);
    await expect(openShare("not-a-real-token")).rejects.toThrow(/not valid/);
  });

  it("stops working the moment it is withdrawn", async () => {
    const document = await signedDocument();
    const { share, token } = await createShare(owner, document.id, { audience: "Acme Ltd" });
    await openShare(token);

    await revokeShare(owner, share.id);

    await expect(openShare(token)).rejects.toThrow(/withdrawn/);
    const summary = (await listShares(owner, document.id))[0];
    expect(summary.state).toBe("WITHDRAWN");
    // The access that happened before withdrawal stays on the record.
    expect(summary.accessCount).toBe(1);
  });

  it("stops working once it expires, without anyone withdrawing it", async () => {
    const document = await signedDocument();
    const { share, token } = await createShare(owner, document.id, { audience: "Acme Ltd", days: 1 });

    await prisma.documentShare.update({ where: { id: share.id }, data: { expiresAt: new Date(Date.now() - 1000) } });

    await expect(openShare(token)).rejects.toThrow(/expired/);
    expect((await listShares(owner, document.id))[0].state).toBe("EXPIRED");
  });

  it("will not share a version with no signature on it", async () => {
    const document = await unsignedDocument();
    await expect(createShare(owner, document.id, { audience: "Acme Ltd" })).rejects.toThrow(/not signed/);
  });

  it("lets only the owner share and withdraw", async () => {
    const document = await signedDocument();
    // `other` is an ADMIN and still may not share a document that is not theirs.
    await expect(createShare(other, document.id, { audience: "Acme Ltd" })).rejects.toThrow(/owner/);

    const { share } = await createShare(owner, document.id, { audience: "Acme Ltd" });
    await expect(revokeShare(other, share.id)).rejects.toThrow(/owner/);
    await expect(revokeShare(viewer, share.id)).rejects.toThrow(AuthorizationError);
  });

  it("rejects an empty audience and an expiry outside the allowed range", async () => {
    const document = await signedDocument();
    await expect(createShare(owner, document.id, { audience: "   " })).rejects.toThrow(/who this is being shared with/);
    await expect(createShare(owner, document.id, { audience: "Acme", days: 0 })).rejects.toThrow(/between 1 and/);
    await expect(createShare(owner, document.id, { audience: "Acme", days: 400 })).rejects.toThrow(/between 1 and/);
  });

  it("refuses to withdraw the same share twice", async () => {
    const document = await signedDocument();
    const { share } = await createShare(owner, document.id, { audience: "Acme Ltd" });
    await revokeShare(owner, share.id);
    await expect(revokeShare(owner, share.id)).rejects.toThrow(/already been withdrawn/);
  });

  it("gives every share a distinct, high-entropy token", async () => {
    const document = await signedDocument();
    const tokens = new Set<string>();
    for (let index = 0; index < 5; index += 1) {
      const { token } = await createShare(owner, document.id, { audience: `Acme ${index}` });
      // 32 random bytes as base64url: no padding, comfortably beyond guessing.
      expect(token.length).toBeGreaterThanOrEqual(43);
      tokens.add(token);
    }
    expect(tokens.size).toBe(5);
  });

  it("keeps the holder's trail on the hash-chained log, not only in the share row", async () => {
    const document = await signedDocument();
    const { share, token } = await createShare(owner, document.id, { audience: "Acme Ltd" });
    await openShare(token);
    await revokeShare(owner, share.id);

    const actions = (await prisma.auditLogEntry.findMany({ orderBy: { seq: "asc" } })).map((entry) => entry.action);
    expect(actions).toContain("DOCUMENT_SHARED");
    expect(actions).toContain("DOCUMENT_SHARE_ACCESSED");
    expect(actions).toContain("DOCUMENT_SHARE_REVOKED");
  });

  it("does not let a share of one document reach another", async () => {
    const mine = await signedDocument();
    const theirs = await signedDocument();
    const { token } = await createShare(owner, mine.id, { audience: "Acme Ltd" });

    const opened = await openShare(token);
    expect(opened.documentId).toBe(mine.id);
    expect(opened.documentId).not.toBe(theirs.id);
  });
});

describe("the share list", () => {
  it("is readable by any role that can read documents", async () => {
    const document = await signedDocument();
    await createShare(owner, document.id, { audience: "Acme Ltd" });
    expect(await listShares(viewer, document.id)).toHaveLength(1);
  });

  it("is empty for a document nobody has shared", async () => {
    await appendAuditEntry({ actorUserId: owner.userId, action: "USER_LOGIN", targetType: "User", targetId: owner.userId });
    expect(await listShares(owner, (await signedDocument()).id)).toEqual([]);
  });
});
