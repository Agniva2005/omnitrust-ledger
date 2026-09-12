// Demo seed data. Grows with each phase; the full fixture set (root CA, three users,
// certificates under all three algorithms, sample documents) lands in Phase 9.
import { prisma } from "../lib/db";

async function main() {
  console.log("Seed: nothing to seed yet (no models before Phase 1).");
}

main()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(() => prisma.$disconnect());
