import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const root = process.cwd();

function run(command: string, args: string[]) {
  console.log(`\n> ${command} ${args.join(" ")}`);
  const binary = process.platform === "win32" ? `${command}.cmd` : command;
  execFileSync(binary, args, { stdio: "inherit" });
}

function ensureEnvFile() {
  const envPath = path.join(root, ".env");
  if (fs.existsSync(envPath)) {
    console.log(".env already exists - leaving it alone.");
    return;
  }
  const template = fs.readFileSync(path.join(root, ".env.example"), "utf8");
  const contents = template.replace(
    /JWT_SECRET="[^"]*"/,
    `JWT_SECRET="${crypto.randomBytes(32).toString("hex")}"`,
  );
  fs.writeFileSync(envPath, contents);
  console.log("Created .env with a freshly generated JWT_SECRET.");
}

function ensureStorage() {
  for (const dir of ["storage", "storage/documents", "storage/keys"]) {
    fs.mkdirSync(path.join(root, dir), { recursive: true });
  }
  const keyPath = path.join(root, "storage/keys/master.key");
  if (fs.existsSync(keyPath)) {
    console.log("Master encryption key already present - leaving it alone.");
    return;
  }
  fs.writeFileSync(keyPath, crypto.randomBytes(32).toString("base64"), { mode: 0o600 });
  console.log("Generated storage/keys/master.key (demo-grade: a local file, not an HSM/KMS).");
}

ensureEnvFile();
ensureStorage();
run("npx", ["prisma", "generate"]);

const migrationsDir = path.join(root, "prisma", "migrations");
if (fs.existsSync(migrationsDir)) {
  run("npx", ["prisma", "migrate", "deploy"]);
} else {
  console.log("\nNo migrations committed yet - skipping `prisma migrate deploy`.");
}

if (fs.existsSync(path.join(root, "prisma", "seed.ts"))) {
  run("npx", ["tsx", "prisma/seed.ts"]);
} else {
  console.log("No prisma/seed.ts yet - skipping seed (lands in Phase 9).");
}

console.log("\nSetup complete. Start the app with: npm run dev");
