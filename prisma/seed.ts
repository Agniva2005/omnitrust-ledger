import { prisma } from "../lib/db";
import { DEMO_PASSWORD, seedCertificates, seedUsers } from "./fixtures";

async function main() {
  const users = await seedUsers();
  console.log(`Seeded ${users.length} demo users (password: ${DEMO_PASSWORD}).`);

  const certificates = await seedCertificates();
  console.log(
    `Root CA ready; ${certificates.length} certificates for signer@demo: ` +
      certificates.map((certificate) => certificate.algorithm).join(", "),
  );
}

main()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(() => prisma.$disconnect());
