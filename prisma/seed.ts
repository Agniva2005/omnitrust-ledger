import { prisma } from "../lib/db";
import { DEMO_PASSWORD, seedUsers } from "./fixtures";

async function main() {
  const users = await seedUsers();
  console.log(`Seeded ${users.length} demo users (password: ${DEMO_PASSWORD}).`);
}

main()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(() => prisma.$disconnect());
