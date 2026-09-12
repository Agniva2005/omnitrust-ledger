// Reusable demo fixtures, shared by prisma/seed.ts and the test suite.
// Grows with each phase; the full set (root CA, certificates under all three
// algorithms, sample documents including a pre-tampered one) lands in Phase 9.
import { prisma } from "../lib/db";
import { hashPassword } from "../lib/auth/session";
import type { Role } from "../lib/auth/rbac";
import { ALGORITHMS } from "../lib/crypto/types";
import { ensureRootCa } from "../lib/pki/ca";
import { issueCertificate } from "../lib/pki/certificates";

export const DEMO_PASSWORD = "demo1234";

export const DEMO_USERS: { email: string; role: Role }[] = [
  { email: "admin@demo", role: "ADMIN" },
  { email: "signer@demo", role: "SIGNER" },
  { email: "verifier@demo", role: "VERIFIER" },
  { email: "viewer@demo", role: "VIEWER" },
];

/** One ACTIVE certificate per algorithm for signer@demo, issued by the local root CA. */
export async function seedCertificates() {
  await ensureRootCa();

  const signer = await prisma.user.findUniqueOrThrow({ where: { email: "signer@demo" } });
  const actor = { userId: signer.id, email: signer.email, role: "SIGNER" as const };

  const issued = [];
  for (const algorithm of ALGORITHMS) {
    const existing = await prisma.certificate.findFirst({
      where: { subjectUserId: signer.id, algorithm, status: "ACTIVE" },
    });
    issued.push(existing ?? (await issueCertificate({ actor, algorithm })));
  }
  return issued;
}

export async function seedUsers() {
  const passwordHash = await hashPassword(DEMO_PASSWORD);
  const users = [];
  for (const user of DEMO_USERS) {
    users.push(
      await prisma.user.upsert({
        where: { email: user.email },
        update: { role: user.role },
        create: { email: user.email, role: user.role, passwordHash },
      }),
    );
  }
  return users;
}
