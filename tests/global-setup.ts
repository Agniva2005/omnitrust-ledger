// Builds a throwaway SQLite database (prisma/test.db) before the suite runs, so
// tests never touch the dev database.
//
// Deletes the previous test.db and applies the committed migrations forward with
// `migrate deploy`. Deliberately avoids `db push --force-reset`: no destructive
// Prisma command is ever run here, and applying the real migrations means the
// suite also proves the committed migration history builds a working schema.
import fs from "node:fs";
import path from "node:path";
import { prismaCliQuiet } from "../lib/prisma-cli";

export default function setup() {
  const root = process.cwd();

  fs.rmSync(path.join(root, "storage", "test"), { recursive: true, force: true });
  for (const suffix of ["", "-journal"]) {
    fs.rmSync(path.join(root, "prisma", `test.db${suffix}`), { force: true });
  }

  prismaCliQuiet(["migrate", "deploy"], { DATABASE_URL: "file:./test.db" });
}
