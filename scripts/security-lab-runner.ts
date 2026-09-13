// Security Lab child process: runs one attack scenario inside the sandbox whose database,
// storage root and master key lib/security-lab/sandbox.ts passed in the environment, then
// prints a single result line. Started only by the sandbox manager; runScenario() refuses to
// execute if the environment is not a sandbox.
//
//   node node_modules/tsx/dist/cli.mjs scripts/security-lab-runner.ts <scenario-id>
import { prisma } from "../lib/db";
import { RESULT_MARKER } from "../lib/security-lab/protocol";
import { runScenario } from "../lib/security-lab/scenarios";

async function main() {
  const id = process.argv[2];
  const result = await runScenario(id);
  process.stdout.write(`\n${RESULT_MARKER}${JSON.stringify(result)}\n`);
}

main()
  .catch((error) => {
    process.stdout.write(`\n${RESULT_MARKER}${JSON.stringify({ refused: error instanceof Error ? error.message : String(error) })}\n`);
    process.exitCode = 1;
  })
  .finally(() => prisma.$disconnect());
