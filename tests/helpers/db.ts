import { prisma } from "@/lib/db";

/**
 * Truncates the test database in foreign-key order. Extended as each phase adds
 * tables, so test files never need to know the dependency graph themselves.
 */
export async function resetDatabase() {
  await prisma.documentVersion.deleteMany();
  await prisma.document.deleteMany();
  await prisma.user.deleteMany();
}
