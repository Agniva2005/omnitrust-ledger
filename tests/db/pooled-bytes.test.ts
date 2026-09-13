// Walkthrough finding: opening the ECDSA or Ed25519 sample document under `next dev` broke the
// whole server. Prisma returned the signature's CMS blob (2.5 KB) as a view into Node's shared
// 8 KB Buffer pool. React's development renderer records the resolved values of promises a
// server component awaits, and enqueues binary chunks larger than 2048 bytes into a byte
// ReadableStream, which transfers the chunk's ArrayBuffer. Transferring the pool detached it
// for the process, so every later small Buffer.from threw ERR_BUFFER_OUT_OF_BOUNDS, responses
// were cut off mid-stream and even request logging failed. lib/db.ts now copies Bytes results
// out of the pool.
import { spawnSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import { detachBytesFromPool, prisma } from "@/lib/db";

// Runs in a child process: detaching the pool in the test runner would break the runner itself.
// The child reports through its exit code because, once the pool is detached, writing to
// stdout fails too (the same reason `next dev` stopped logging).
function probeAfterEnqueue(copyFirst: boolean): string {
  const script = `
    const pooled = Buffer.from("x".repeat(3000));
    let view = new Uint8Array(pooled.buffer, pooled.byteOffset, pooled.byteLength);
    if (${copyFirst}) view = new Uint8Array(view);
    new ReadableStream({ type: "bytes", start(controller) { controller.enqueue(view); } });
    let code = 0;
    try { Buffer.from("probe"); } catch (error) { code = error.code === "ERR_BUFFER_OUT_OF_BOUNDS" ? 3 : 4; }
    process.reallyExit(code);
  `;
  const result = spawnSync(process.execPath, ["-e", script]);
  return { 0: "pool-intact", 3: "ERR_BUFFER_OUT_OF_BOUNDS", 4: "other error" }[result.status ?? -1] ?? `exit ${result.status}`;
}

describe("Bytes values and Node's shared Buffer pool", () => {
  it("reproduces the failure: enqueueing a pooled view into a byte stream breaks later allocations", () => {
    expect(probeAfterEnqueue(false)).toBe("ERR_BUFFER_OUT_OF_BOUNDS");
  });

  it("a copy owning its ArrayBuffer can be transferred without touching the pool", () => {
    expect(probeAfterEnqueue(true)).toBe("pool-intact");
  });

  it("detachBytesFromPool copies pooled views, including nested ones, and keeps the bytes", () => {
    const pooled = Buffer.from("nested signature bytes");
    expect(pooled.buffer.byteLength).toBeGreaterThan(pooled.byteLength);

    const signedAt = new Date("2026-01-01T00:00:00Z");
    const result = detachBytesFromPool({
      signatureBytes: pooled,
      signedAt,
      certificate: { der: [pooled] },
      cmsSignature: null,
    });

    for (const bytes of [result.signatureBytes, result.certificate.der[0]]) {
      expect(bytes.byteOffset).toBe(0);
      expect(bytes.buffer.byteLength).toBe(bytes.byteLength);
      expect(bytes.buffer).not.toBe(pooled.buffer);
      expect(Buffer.from(bytes).toString()).toBe("nested signature bytes");
    }
    expect(result.signedAt).toBe(signedAt);
    expect(result.cmsSignature).toBeNull();
  });

  it("leaves a Uint8Array that already owns its buffer alone", () => {
    const owned = new Uint8Array([1, 2, 3]);
    expect(detachBytesFromPool(owned)).toBe(owned);
  });

  it("the Prisma client returns Bytes that own their ArrayBuffer", async () => {
    const rows = await prisma.$queryRaw<{ blob: Uint8Array }[]>`SELECT randomblob(2546) AS blob`;
    const blob = rows[0].blob;
    expect(blob).toBeInstanceOf(Uint8Array);
    expect(blob.byteLength).toBe(2546);
    expect(blob.byteOffset).toBe(0);
    expect(blob.buffer.byteLength).toBe(2546);
  });
});
