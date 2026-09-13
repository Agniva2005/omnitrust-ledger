import { PrismaClient } from "@prisma/client";

/**
 * Returns `value` with every Uint8Array replaced by a copy that owns its ArrayBuffer.
 *
 * Prisma materialises small `Bytes` columns as views into Node's shared Buffer pool, an
 * 8 KB ArrayBuffer that later unrelated allocations also use. Anything that transfers a
 * view's ArrayBuffer detaches that pool for the whole process, after which every small
 * `Buffer.from` throws ERR_BUFFER_OUT_OF_BOUNDS. React's development renderer does exactly
 * that: it records the resolved values of promises a server component awaits and enqueues
 * binary chunks larger than 2048 bytes into a byte ReadableStream, which transfers them. A
 * document page awaiting a signature with a pooled 2.5 KB CMS blob took down `next dev`.
 * Copying out of the pool keeps any such transfer confined to bytes nobody else shares.
 */
export function detachBytesFromPool<T>(value: T): T {
  if (value instanceof Uint8Array) {
    return (value.byteOffset === 0 && value.byteLength === value.buffer.byteLength
      ? value
      : new Uint8Array(value)) as T;
  }
  if (Array.isArray(value)) return value.map((item) => detachBytesFromPool(item)) as T;
  if (value !== null && typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype) {
    for (const [key, field] of Object.entries(value)) {
      (value as Record<string, unknown>)[key] = detachBytesFromPool(field);
    }
  }
  return value;
}

function createClient(): PrismaClient {
  return new PrismaClient().$extends({
    query: {
      async $allOperations({ args, query }) {
        return detachBytesFromPool(await query(args));
      },
    },
  }) as unknown as PrismaClient;
}

const globalForPrisma = globalThis as unknown as { prisma?: PrismaClient };

export const prisma = globalForPrisma.prisma ?? createClient();

if (process.env.NODE_ENV !== "production") globalForPrisma.prisma = prisma;
