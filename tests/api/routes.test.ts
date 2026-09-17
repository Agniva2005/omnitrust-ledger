// Route-level tests for every API route the Phase 0 audit found exercised only through its
// service functions. Each handler runs for real (session lookup, RBAC, validation, the service
// layer, status mapping); only next/headers is replaced, because it exists only inside a
// Next.js request scope. Every response body is also checked for key material and password
// hashes, since no API may return either.
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { Role } from "@/lib/auth/rbac";
import { COOKIE_NAME, createSessionToken } from "@/lib/auth/session";
import { ALGORITHMS } from "@/lib/crypto/orchestrator";
import { prisma } from "@/lib/db";
import { ensureRootCa } from "@/lib/pki/ca";
import { CA_ALGORITHM } from "@/lib/pki/policy";
import { seedUsers } from "@/prisma/fixtures";
import { resetDatabase } from "@/tests/helpers/db";
import { ensureMasterKey } from "@/tests/helpers/master-key";

const session = vi.hoisted(() => ({ token: null as string | null }));
vi.mock("next/headers", () => ({
  cookies: async () => ({
    get: (name: string) => (name === COOKIE_NAME && session.token ? { name, value: session.token } : undefined),
  }),
}));

const me = await import("@/app/api/auth/me/route");
const documents = await import("@/app/api/documents/route");
const document = await import("@/app/api/documents/[id]/route");
const versions = await import("@/app/api/documents/[id]/versions/route");
const sign = await import("@/app/api/documents/[id]/sign/route");
const verify = await import("@/app/api/documents/[id]/verify/route");
const demoTamper = await import("@/app/api/documents/[id]/demo-tamper/route");
const evidence = await import("@/app/api/documents/[id]/evidence/route");
const shares = await import("@/app/api/documents/[id]/shares/route");
const shareItem = await import("@/app/api/shares/[shareId]/route");
const shareEvidence = await import("@/app/api/share/[token]/evidence/route");
const certificates = await import("@/app/api/certificates/route");
const revoke = await import("@/app/api/certificates/[id]/revoke/route");
const certificateEvidence = await import("@/app/api/certificates/[id]/evidence/route");
const auditVerify = await import("@/app/api/audit/verify/route");
const auditTamper = await import("@/app/api/audit/demo-tamper/route");
const auditExport = await import("@/app/api/audit/export/route");
const auditCheckpoints = await import("@/app/api/audit/checkpoints/route");
const anchoring = await import("@/app/api/anchoring/route");
const anchorBatches = await import("@/app/api/anchoring/batches/route");
const anchorVerify = await import("@/app/api/anchoring/verify/route");
const anchorNode = await import("@/app/api/anchoring/node/route");
const securityLab = await import("@/app/api/security-lab/route");
const labEvaluation = await import("@/app/api/security-lab/evaluation/route");

const BASE = "http://localhost";

beforeAll(async () => {
  ensureMasterKey();
  await resetDatabase();
  await seedUsers();
  await ensureRootCa();
}, 60_000);

beforeEach(() => {
  session.token = null;
});

async function as(email: string | null) {
  if (email === null) {
    session.token = null;
    return;
  }
  const user = await prisma.user.findUniqueOrThrow({ where: { email } });
  session.token = await createSessionToken({ userId: user.id, email: user.email, role: user.role as Role });
}

const params = (id: string) => ({ params: Promise.resolve({ id }) });

const json = (url: string, method: string, body?: unknown) =>
  new Request(`${BASE}${url}`, {
    method,
    headers: { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });

function upload(url: string, contents: string | null, filename = `route-${Math.random().toString(36).slice(2)}.txt`) {
  const form = new FormData();
  if (contents !== null) form.append("file", new File([contents], filename, { type: "text/plain" }));
  return new Request(`${BASE}${url}`, { method: "POST", body: form });
}

/** Reads a response and asserts it carries no key material, password hash or stack trace. */
async function read(response: Response) {
  const text = await response.text();
  expect(text).not.toMatch(/PRIVATE KEY/);
  expect(text).not.toMatch(/encryptedPrivateKey/);
  expect(text).not.toMatch(/passwordHash/);
  expect(text).not.toMatch(/\$2[aby]\$\d\d\$/);
  expect(text).not.toMatch(/\n\s+at \S+ \(/);
  return { status: response.status, body: text ? JSON.parse(text) : null };
}

async function uploadAsSigner(contents = `document ${Math.random()}`) {
  await as("signer@demo");
  const { status, body } = await read(await documents.POST(upload("/api/documents", contents)));
  expect(status).toBe(201);
  return body.document as { id: string; filename: string };
}

async function issueAs(email: string, algorithm: string = CA_ALGORITHM) {
  await as(email);
  const { status, body } = await read(await certificates.POST(json("/api/certificates", "POST", { algorithm })));
  expect(status).toBe(201);
  return body.certificate as { id: string; serialNumber: string; algorithm: string };
}

describe("GET /api/auth/me", () => {
  it("is 401 with no user when signed out, and returns the role's capabilities when signed in", async () => {
    await as(null);
    expect(await read(await me.GET())).toEqual({ status: 401, body: { user: null } });

    await as("viewer@demo");
    const { status, body } = await read(await me.GET());
    expect(status).toBe(200);
    expect(body.user).toMatchObject({ email: "viewer@demo", role: "VIEWER" });
    expect(body.capabilities).toContain("document:read");
    expect(body.capabilities).not.toContain("document:upload");
  });
});

describe("documents", () => {
  it("POST /api/documents: 401 signed out, 403 for a viewer, 400 without a file, 201 for a signer, 409 for a duplicate", async () => {
    await as(null);
    expect((await read(await documents.POST(upload("/api/documents", "x")))).status).toBe(401);

    await as("viewer@demo");
    expect((await read(await documents.POST(upload("/api/documents", "viewer upload")))).status).toBe(403);

    await as("signer@demo");
    const missing = await read(await documents.POST(upload("/api/documents", null)));
    expect(missing).toMatchObject({ status: 400, body: { error: expect.stringMatching(/file/) } });

    const created = await read(await documents.POST(upload("/api/documents", "a unique upload body")));
    expect(created.status).toBe(201);
    expect(created.body.document.currentHash).toMatch(/^[0-9a-f]{64}$/);

    expect((await read(await documents.POST(upload("/api/documents", "a unique upload body")))).status).toBe(409);
    expect((await read(await documents.POST(upload("/api/documents", "")))).status).toBe(400);
  });

  it("GET /api/documents and /api/documents/:id: readable by a viewer, 404 for an unknown id, 401 signed out", async () => {
    const created = await uploadAsSigner();

    await as("viewer@demo");
    const list = await read(await documents.GET());
    expect(list.status).toBe(200);
    expect(list.body.documents.map((entry: { id: string }) => entry.id)).toContain(created.id);

    const detail = await read(await document.GET(new Request(`${BASE}/api/documents/${created.id}`), params(created.id)));
    expect(detail.status).toBe(200);
    expect(detail.body.document.id).toBe(created.id);

    expect((await read(await document.GET(new Request(`${BASE}/api/documents/nope`), params("nope")))).status).toBe(404);

    await as(null);
    expect((await read(await documents.GET())).status).toBe(401);
  });

  it("POST /api/documents/:id/versions: 403 for a viewer, 400 without a file, 201 for the owner", async () => {
    const created = await uploadAsSigner();
    const url = `/api/documents/${created.id}/versions`;

    await as("viewer@demo");
    expect((await read(await versions.POST(upload(url, "viewer version"), params(created.id)))).status).toBe(403);

    await as("signer@demo");
    expect((await read(await versions.POST(upload(url, null), params(created.id)))).status).toBe(400);
    const added = await read(await versions.POST(upload(url, "second version contents"), params(created.id)));
    expect(added.status).toBe(201);
  });
});

describe("signing and verification", () => {
  it("POST /api/documents/:id/sign: 400 without a certificate, 403 for a verifier or someone else's certificate, 201, then 409", async () => {
    const created = await uploadAsSigner();
    const mine = await issueAs("signer@demo");
    const adminsCertificate = await issueAs("admin@demo");
    const url = `/api/documents/${created.id}/sign`;

    await as("signer@demo");
    expect((await read(await sign.POST(json(url, "POST", {}), params(created.id)))).status).toBe(400);
    expect((await read(await sign.POST(json(url, "POST", { certificateId: adminsCertificate.id }), params(created.id)))).status).toBe(403);

    await as("verifier@demo");
    expect((await read(await sign.POST(json(url, "POST", { certificateId: mine.id }), params(created.id)))).status).toBe(403);

    await as("signer@demo");
    const signed = await read(await sign.POST(json(url, "POST", { certificateId: mine.id }), params(created.id)));
    expect(signed.status).toBe(201);
    expect(signed.body.signature.algorithm).toBe(CA_ALGORITHM);
    expect(Buffer.from(signed.body.signature.signatureBytes, "base64").length).toBe(signed.body.signature.signatureByteLength);
    expect(signed.body.signedHash).toMatch(/^[0-9a-f]{64}$/);

    expect((await read(await sign.POST(json(url, "POST", { certificateId: mine.id }), params(created.id)))).status).toBe(409);
  });

  it("POST /api/documents/:id/verify: 409 notSigned for an unsigned document, 403 for a viewer, 404 unknown, 200 with the full result", async () => {
    const unsigned = await uploadAsSigner();
    await as("verifier@demo");
    const notSigned = await read(await verify.POST(json(`/api/documents/${unsigned.id}/verify`, "POST"), params(unsigned.id)));
    expect(notSigned).toMatchObject({ status: 409, body: { notSigned: true } });

    const signedDocument = await uploadAsSigner();
    const certificate = await issueAs("signer@demo");
    await as("signer@demo");
    await sign.POST(json(`/api/documents/${signedDocument.id}/sign`, "POST", { certificateId: certificate.id }), params(signedDocument.id));

    await as("viewer@demo");
    expect((await read(await verify.POST(json("/x", "POST"), params(signedDocument.id)))).status).toBe(403);

    await as("verifier@demo");
    expect((await read(await verify.POST(json("/x", "POST"), params("nope")))).status).toBe(404);
    const verified = await read(await verify.POST(json("/x", "POST"), params(signedDocument.id)));
    expect(verified.status).toBe(200);
    // This assertion failed once, in a combined run, and did not reproduce; report the verdict's
    // evidence so a recurrence can be diagnosed rather than showing only an outcome mismatch.
    const evidence = JSON.stringify({
      outcome: verified.body.result.outcome,
      reasons: verified.body.result.reasons ?? verified.body.result.reason,
      trust: verified.body.result.trust,
      notPassed: verified.body.result.steps.filter((step: { status: string }) => step.status !== "PASS"),
    });
    expect(verified.body.result.outcome, evidence).toBe("VALID");
    expect(verified.body.result.steps.length).toBeGreaterThanOrEqual(10);
    expect(verified.body.result.trust.trustedTime).not.toBeNull();
  }, 30_000);

  it("GET /api/documents/:id/evidence: 404 unsigned, 403 for a viewer, and a readable archive once signed", async () => {
    const unsigned = await uploadAsSigner();
    await as("signer@demo");
    expect((await read(await evidence.GET(new Request(`${BASE}/api/documents/${unsigned.id}/evidence`), params(unsigned.id)))).status).toBe(404);

    const created = await uploadAsSigner();
    const certificate = await issueAs("signer@demo");
    await as("signer@demo");
    await sign.POST(json(`/api/documents/${created.id}/sign`, "POST", { certificateId: certificate.id }), params(created.id));

    await as("viewer@demo");
    expect((await read(await evidence.GET(new Request(`${BASE}/api/documents/${created.id}/evidence`), params(created.id)))).status).toBe(403);

    await as("signer@demo");
    const response = await evidence.GET(new Request(`${BASE}/api/documents/${created.id}/evidence`), params(created.id));
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("application/zip");
    expect(response.headers.get("content-disposition")).toMatch(/evidence\.zip/);

    const archive = Buffer.from(await response.arrayBuffer());
    // "PK" and an end-of-central-directory record: a reader can open it.
    expect(archive.subarray(0, 4)).toEqual(Buffer.from([0x50, 0x4b, 0x03, 0x04]));
    expect(archive.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]))).toBeGreaterThan(0);
    expect(archive.includes(Buffer.from("README.txt"))).toBe(true);
    expect(archive.includes(Buffer.from("verification.json"))).toBe(true);
    // The pack must never carry key material.
    expect(archive.includes(Buffer.from("PRIVATE KEY"))).toBe(false);
  }, 60_000);

  it("shares: minted once, openable without a session, dead the moment it is withdrawn", async () => {
    const created = await uploadAsSigner();
    const certificate = await issueAs("signer@demo");
    await as("signer@demo");
    await sign.POST(json(`/api/documents/${created.id}/sign`, "POST", { certificateId: certificate.id }), params(created.id));

    const url = `/api/documents/${created.id}/shares`;
    await as("viewer@demo");
    expect((await read(await shares.POST(json(url, "POST", { audience: "Acme" }), params(created.id)))).status).toBe(403);

    await as("signer@demo");
    expect((await read(await shares.POST(json(url, "POST", {}), params(created.id)))).status).toBe(400);

    const minted = await read(await shares.POST(json(url, "POST", { audience: "Acme Ltd", days: 7 }), params(created.id)));
    expect(minted.status).toBe(201);
    const token = minted.body.token as string;
    expect(token.length).toBeGreaterThanOrEqual(43);

    // The whole point: no session at all, and the evidence still comes back.
    await as(null);
    const pack = await shareEvidence.GET(new Request(`${BASE}/x`), { params: Promise.resolve({ token }) });
    expect(pack.status).toBe(200);
    expect(pack.headers.get("content-type")).toBe("application/zip");
    const archive = Buffer.from(await pack.arrayBuffer());
    expect(archive.includes(Buffer.from("PRIVATE KEY"))).toBe(false);

    const unknown = await shareEvidence.GET(new Request(`${BASE}/x`), { params: Promise.resolve({ token: "nope" }) });
    expect(unknown.status).toBe(404);

    await as("signer@demo");
    const listed = await read(await shares.GET(new Request(`${BASE}${url}`), params(created.id)));
    expect(listed.body.shares[0].state).toBe("ACTIVE");

    const withdrawn = await read(await shareItem.DELETE(new Request(`${BASE}/x`), { params: Promise.resolve({ shareId: listed.body.shares[0].id }) }));
    expect(withdrawn.body.share.state).toBe("WITHDRAWN");

    await as(null);
    const afterWithdrawal = await shareEvidence.GET(new Request(`${BASE}/x`), { params: Promise.resolve({ token }) });
    expect(afterWithdrawal.status).toBe(404);
  }, 60_000);

  it("GET /api/security-lab/evaluation: 403 below ADMIN, and an archive naming what was never run", async () => {
    await as("signer@demo");
    expect((await read(await labEvaluation.GET())).status).toBe(403);

    await as("admin@demo");
    const response = await labEvaluation.GET();
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("application/zip");

    const archive = Buffer.from(await response.arrayBuffer());
    expect(archive.subarray(0, 4)).toEqual(Buffer.from([0x50, 0x4b, 0x03, 0x04]));
    expect(archive.includes(Buffer.from("evaluation.json"))).toBe(true);
    expect(archive.includes(Buffer.from("adversaries.json"))).toBe(true);
    // The README must say a scenario nobody ran is not a pass, or the pack overstates itself.
    expect(archive.includes(Buffer.from("is not a pass"))).toBe(true);
  }, 60_000);

  it("GET /api/certificates/:id/evidence: 404 unknown, and an archive any role may read", async () => {
    const certificate = await issueAs("signer@demo");

    await as("viewer@demo");
    expect((await read(await certificateEvidence.GET(new Request(`${BASE}/x`), params("nope")))).status).toBe(404);

    // Every role can read certificates, so every role can take the evidence away.
    const response = await certificateEvidence.GET(new Request(`${BASE}/x`), params(certificate.id));
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("application/zip");

    const archive = Buffer.from(await response.arrayBuffer());
    expect(archive.subarray(0, 4)).toEqual(Buffer.from([0x50, 0x4b, 0x03, 0x04]));
    for (const name of ["certificate.pem", "ca.pem", "crl.pem", "explorer.json", "README.txt"]) {
      expect(archive.includes(Buffer.from(name)), name).toBe(true);
    }
    expect(archive.includes(Buffer.from("PRIVATE KEY"))).toBe(false);
  }, 60_000);

  it("GET /api/audit/export: 403 for a viewer, and a readable archive for a verifier", async () => {
    await as("viewer@demo");
    expect((await read(await auditExport.GET())).status).toBe(403);

    await as("verifier@demo");
    const response = await auditExport.GET();
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("application/zip");

    const archive = Buffer.from(await response.arrayBuffer());
    expect(archive.subarray(0, 4)).toEqual(Buffer.from([0x50, 0x4b, 0x03, 0x04]));
    expect(archive.includes(Buffer.from("entries.json"))).toBe(true);
    expect(archive.includes(Buffer.from("integrity.json"))).toBe(true);
    expect(archive.includes(Buffer.from("PRIVATE KEY"))).toBe(false);
  }, 60_000);

  it("POST /api/anchoring/node: 403 below ADMIN and 400 for an unknown action; GET reports status", async () => {
    const url = "/api/anchoring/node";

    // Deliberately no start/stop here: those spawn a chain process, which a test must not do.
    await as("signer@demo");
    expect((await read(await anchorNode.POST(json(url, "POST", { action: "start" })))).status).toBe(403);

    await as("admin@demo");
    expect((await read(await anchorNode.POST(json(url, "POST", { action: "nonsense" })))).status).toBe(400);

    const status = await read(await anchorNode.GET());
    expect(status.status).toBe(200);
    expect(status.body.node).toMatchObject({ rpcUrl: expect.stringMatching(/^https?:\/\//) });
    expect(typeof status.body.node.reachable).toBe("boolean");
  }, 30_000);

  it("POST /api/audit/demo-tamper: 403 below ADMIN, 400 without a sequence, and reports state", async () => {
    const url = "/api/audit/demo-tamper";

    await as("signer@demo");
    expect((await read(await auditTamper.POST(json(url, "POST", { action: "edit", seq: 1 })))).status).toBe(403);

    await as("admin@demo");
    expect((await read(await auditTamper.POST(json(url, "POST", { action: "edit" })))).status).toBe(400);
    expect((await read(await auditTamper.POST(json(url, "POST", { action: "nonsense", seq: 1 })))).status).toBe(400);
    // Restoring a log nobody altered is a conflict, not a silent success.
    expect((await read(await auditTamper.POST(json(url, "POST", { action: "restore" })))).status).toBe(409);

    const state = await read(await auditTamper.GET());
    expect(state.status).toBe(200);
    expect(state.body.state.altered).toBe(false);
  });

  it("POST /api/documents/:id/demo-tamper: 403 below ADMIN, 400 for an unknown action, then alters and restores", async () => {
    const created = await uploadAsSigner();
    const certificate = await issueAs("signer@demo");
    await as("signer@demo");
    await sign.POST(json(`/api/documents/${created.id}/sign`, "POST", { certificateId: certificate.id }), params(created.id));

    const url = `/api/documents/${created.id}/demo-tamper`;

    // The capability is ADMIN-only, so the role that may sign still may not tamper.
    expect((await read(await demoTamper.POST(json(url, "POST", { action: "signature" }), params(created.id)))).status).toBe(403);

    await as("admin@demo");
    expect((await read(await demoTamper.POST(json(url, "POST", { action: "nonsense" }), params(created.id)))).status).toBe(400);

    const altered = await read(await demoTamper.POST(json(url, "POST", { action: "signature" }), params(created.id)));
    expect(altered.status).toBe(200);
    expect(altered.body.state.signatureAltered).toBe(true);

    const broken = await read(await verify.POST(json("/x", "POST"), params(created.id)));
    expect(broken.body.result.outcome).toBe("INVALID");
    expect(broken.body.result.reason).toBe("SIGNATURE_INVALID");

    const restored = await read(await demoTamper.POST(json(url, "POST", { action: "restore" }), params(created.id)));
    expect(restored.status).toBe(200);
    expect(restored.body.state.signatureAltered).toBe(false);

    const state = await read(await demoTamper.GET(json(url, "GET"), params(created.id)));
    expect(state.status).toBe(200);
    expect(state.body.state.storedHash).toBe(state.body.state.signedHash);

    expect((await read(await verify.POST(json("/x", "POST"), params(created.id)))).body.result.outcome).toBe("VALID");
  }, 30_000);
});

describe("certificates", () => {
  it("POST /api/certificates: 403 for a viewer, 400 for an unknown algorithm, 201 without any key material", async () => {
    await as("viewer@demo");
    expect((await read(await certificates.POST(json("/api/certificates", "POST", { algorithm: CA_ALGORITHM })))).status).toBe(403);

    await as("signer@demo");
    const unknown = await read(await certificates.POST(json("/api/certificates", "POST", { algorithm: "DSA_512" })));
    expect(unknown.status).toBe(400);
    for (const algorithm of ALGORITHMS) expect(unknown.body.error).toContain(algorithm);

    const issued = await read(await certificates.POST(json("/api/certificates", "POST", { algorithm: CA_ALGORITHM })));
    expect(issued.status).toBe(201);
    expect(issued.body.certificate.certPem).toMatch(/BEGIN CERTIFICATE/);
    expect(issued.body.certificate).not.toHaveProperty("keyPair.encryptedPrivateKey");
  });

  it("GET /api/certificates: readable by a viewer, never with key material", async () => {
    await issueAs("signer@demo");
    await as("viewer@demo");
    const listed = await read(await certificates.GET());
    expect(listed.status).toBe(200);
    expect(listed.body.certificates.length).toBeGreaterThan(0);
  });

  it("POST /api/certificates/:id/revoke: 403 for a non-admin, 400 for a bad reason or a future invalidity date, 200, then 409", async () => {
    const certificate = await issueAs("signer@demo");
    const url = `/api/certificates/${certificate.id}/revoke`;

    await as("signer@demo");
    expect((await read(await revoke.POST(json(url, "POST", { reason: "keyCompromise" }), params(certificate.id)))).status).toBe(403);

    await as("admin@demo");
    expect((await read(await revoke.POST(json(url, "POST", { reason: "becauseISaidSo" }), params(certificate.id)))).status).toBe(400);
    const future = new Date(Date.now() + 86_400_000).toISOString();
    expect((await read(await revoke.POST(json(url, "POST", { reason: "keyCompromise", invalidityDate: future }), params(certificate.id)))).status).toBe(400);

    const revoked = await read(await revoke.POST(json(url, "POST", { reason: "superseded", comment: "route test" }), params(certificate.id)));
    expect(revoked.status).toBe(200);
    expect(revoked.body.certificate).toMatchObject({ status: "REVOKED", revocationReason: "superseded" });

    expect((await read(await revoke.POST(json(url, "POST", { reason: "superseded" }), params(certificate.id)))).status).toBe(409);
    expect((await read(await revoke.POST(json("/x", "POST", {}), params("nope")))).status).toBe(404);
  });
});

describe("audit", () => {
  it("POST /api/audit/verify: 403 for a viewer, 200 with the reconciled result for a verifier", async () => {
    await as("viewer@demo");
    expect((await read(await auditVerify.POST())).status).toBe(403);

    await as("verifier@demo");
    const result = await read(await auditVerify.POST());
    expect(result.status).toBe(200);
    expect(result.body.result).toMatchObject({ valid: true, chain: { valid: true } });
    expect(result.body.result.limitations.length).toBeGreaterThan(0);
  });

  it("/api/audit/checkpoints: listing for any reader, creation for an admin only", async () => {
    await as("verifier@demo");
    expect((await read(await auditCheckpoints.POST())).status).toBe(403);

    await as("admin@demo");
    const created = await read(await auditCheckpoints.POST());
    expect(created.status).toBe(201);
    expect(created.body.checkpoint).toMatchObject({ timestamped: true });

    await as("viewer@demo");
    const listed = await read(await auditCheckpoints.GET());
    expect(listed.status).toBe(200);
    expect(listed.body.checkpoints[0].id).toBe(created.body.checkpoint.id);

    await as(null);
    expect((await read(await auditCheckpoints.GET())).status).toBe(401);
  }, 30_000);
});

describe("anchoring (against the test chain)", () => {
  it("overview for any reader; anchoring for an admin only, then 409 when nothing is pending; verification by kind and target", async () => {
    await as("viewer@demo");
    const overview = await read(await anchoring.GET());
    expect(overview.status).toBe(200);
    expect(overview.body.chain.reachable).toBe(true);
    expect(overview.body.pending.total).toBeGreaterThan(0);

    await as("signer@demo");
    expect((await read(await anchorBatches.POST())).status).toBe(403);

    await as("admin@demo");
    const anchored = await read(await anchorBatches.POST());
    expect(anchored.status).toBe(201);
    expect(anchored.body.batch.root).toMatch(/^[0-9a-f]{64}$/);
    expect((await read(await anchorBatches.POST())).status).toBe(409);

    const leaf = await prisma.anchorLeaf.findFirstOrThrow({ where: { batchId: anchored.body.batch.id } });
    await as("viewer@demo");
    const verifyUrl = (query: string) => new Request(`${BASE}/api/anchoring/verify?${query}`);
    expect((await read(await anchorVerify.GET(verifyUrl(`kind=DOCUMENT&target=${leaf.targetId}`)))).status).toBe(400);
    expect((await read(await anchorVerify.GET(verifyUrl("kind=SIGNATURE")))).status).toBe(400);
    const verified = await read(await anchorVerify.GET(verifyUrl(`kind=${leaf.kind}&target=${leaf.targetId}`)));
    expect(verified.status).toBe(200);
    expect(verified.body.result.status).toBe("VALID");

    await as(null);
    expect((await read(await anchoring.GET())).status).toBe(401);
  }, 60_000);
});

describe("security lab (refusals only; real runs are covered in tests/security-lab)", () => {
  it("lists scenarios for an admin only, and refuses bad or unauthorised runs before starting a sandbox", async () => {
    await as("verifier@demo");
    expect((await read(await securityLab.GET())).status).toBe(403);
    expect((await read(await securityLab.POST(json("/api/security-lab", "POST", { scenario: "control-untouched" })))).status).toBe(403);

    await as("admin@demo");
    const listed = await read(await securityLab.GET());
    expect(listed.status).toBe(200);
    expect(listed.body.scenarios.length).toBeGreaterThan(10);
    expect((await read(await securityLab.POST(json("/api/security-lab", "POST", { scenario: "drop-database" })))).status).toBe(400);
    expect((await read(await securityLab.POST(new Request(`${BASE}/api/security-lab`, { method: "POST", body: "not json" })))).status).toBe(400);

    await as(null);
    expect((await read(await securityLab.GET())).status).toBe(401);
  });
});
