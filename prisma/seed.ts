import { prisma } from "../lib/db";
import { verifyAuditChain } from "../lib/audit/integrity";
import { DEMO_PASSWORD, seedAll } from "./fixtures";

async function main() {
  const { users, certificates, documents } = await seedAll();

  console.log(`Users        : ${users.length} (password for all: ${DEMO_PASSWORD})`);
  console.log(
    `Certificates : ${Object.keys(certificates).join(", ")} for signer@demo, plus one expired`,
  );
  console.log(`Documents    :`);
  console.log(`  unsigned   : ${documents.unsigned.filename}`);
  for (const [key, document] of Object.entries(documents.signed)) {
    console.log(`  signed     : ${document.filename} (${key})`);
  }
  console.log(`  tampered   : ${documents.tampered.filename} (verification will report INVALID)`);

  const chain = await verifyAuditChain();
  console.log(
    `Audit log    : ${chain.entriesChecked} entries, chain ${chain.valid ? "intact" : "BROKEN"}`,
  );
  console.log("\nNext: npm run dev, then follow DEMO_SCRIPT.md");
}

main()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(() => prisma.$disconnect());
