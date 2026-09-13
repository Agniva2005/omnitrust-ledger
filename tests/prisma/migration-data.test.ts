// The Phase 4 migration converts free-text revocation reasons recorded before it into RFC
// 5280 reason codes. The suite otherwise only ever migrates an empty database, so this
// runs that data step's actual SQL, read from the migration file, against rows shaped like
// pre-migration data, and checks the SQL's list of reasons cannot drift from the code's.
import fs from "node:fs";
import path from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import type { Actor } from "@/lib/auth/rbac";
import { prisma } from "@/lib/db";
import { ensureRootCa } from "@/lib/pki/ca";
import { issueCertificate } from "@/lib/pki/certificates";
import { REVOCATION_REASONS } from "@/lib/pki/revocation";
import { seedUsers } from "@/prisma/fixtures";
import { resetDatabase } from "@/tests/helpers/db";
import { ensureMasterKey } from "@/tests/helpers/master-key";

const MIGRATION = path.join(
  process.cwd(),
  "prisma",
  "migrations",
  "20260913093000_add_crl_timestamping_revocation_reasons",
  "migration.sql",
);

function dataStep(): string {
  const sql = fs.readFileSync(MIGRATION, "utf8");
  const start = sql.indexOf('UPDATE "Certificate"');
  if (start === -1) throw new Error("data step not found in the migration");
  return sql.slice(start).trim().replace(/;\s*$/, "");
}

let signer: Actor;

beforeAll(async () => {
  ensureMasterKey();
  await resetDatabase();
  await seedUsers();
  await ensureRootCa();
  const user = await prisma.user.findUniqueOrThrow({ where: { email: "signer@demo" } });
  signer = { userId: user.id, email: user.email, role: "SIGNER" };
}, 60_000);

describe("revocation reason data migration", () => {
  it("keeps a free-text reason as the comment and makes the reason unspecified", async () => {
    const [freeText, alreadyCoded, active] = await Promise.all([
      issueCertificate({ actor: signer, algorithm: "ECDSA_P256" }),
      issueCertificate({ actor: signer, algorithm: "ECDSA_P256" }),
      issueCertificate({ actor: signer, algorithm: "ECDSA_P256" }),
    ]);

    // The shape a revoked certificate had before the migration: a free-text reason.
    const revokedAt = new Date();
    await prisma.certificate.update({
      where: { id: freeText.id },
      data: { status: "REVOKED", revokedAt, revocationReason: "Revoked from the certificates page" },
    });
    await prisma.certificate.update({
      where: { id: alreadyCoded.id },
      data: { status: "REVOKED", revokedAt, revocationReason: "superseded" },
    });

    await prisma.$executeRawUnsafe(dataStep());

    const reload = (id: string) => prisma.certificate.findUniqueOrThrow({ where: { id } });

    expect(await reload(freeText.id)).toMatchObject({
      revocationReason: "unspecified",
      revocationComment: "Revoked from the certificates page",
    });
    expect(await reload(alreadyCoded.id)).toMatchObject({
      revocationReason: "superseded",
      revocationComment: null,
    });
    expect(await reload(active.id)).toMatchObject({
      revocationReason: null,
      revocationComment: null,
    });
  });

  it("recognises exactly the reason codes the application accepts", () => {
    const notInList = /NOT IN \(([^)]*)\)/.exec(dataStep())?.[1];
    expect(notInList).toBeDefined();
    const recognised = [...notInList!.matchAll(/'([A-Za-z]+)'/g)].map((match) => match[1]);
    expect([...recognised].sort()).toEqual([...REVOCATION_REASONS].sort());
  });
});
