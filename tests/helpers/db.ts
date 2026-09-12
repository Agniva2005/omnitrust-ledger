import { prisma } from "@/lib/db";

/**
 * Truncates the test database in foreign-key order. Extended as each phase adds
 * tables, so test files never need to know the dependency graph themselves.
 */
export async function resetDatabase() {
  await prisma.signature.deleteMany();
  await prisma.documentVersion.deleteMany();
  await prisma.document.deleteMany();
  await prisma.certificate.deleteMany();
  await prisma.keyPair.deleteMany();
  await prisma.certificateAuthority.deleteMany();
  await prisma.user.deleteMany();
}
