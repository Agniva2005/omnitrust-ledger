// Security Lab: the isolation guard. Every attack scenario calls this before touching anything.
//
// A scenario deliberately corrupts documents, signatures, CRLs and the audit log. It may only
// do so where all three stores it can reach (the database, the document storage root and the
// master key) are disposable: a per-run sandbox directory created by lib/security-lab/sandbox.ts,
// or the throwaway test database while the test suite runs.
import path from "node:path";

export class SandboxViolationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SandboxViolationError";
  }
}

type Env = Record<string, string | undefined>;

export function labRoot(env: Env = process.env): string {
  return path.resolve(env.SECURITY_LAB_ROOT ?? path.join(process.cwd(), "storage", "lab"));
}

/** Resolves a Prisma SQLite URL the way Prisma does: relative paths are relative to prisma/. */
export function sqliteFile(databaseUrl: string | undefined): string | null {
  if (!databaseUrl?.startsWith("file:")) return null;
  const location = databaseUrl.slice("file:".length).split("?")[0];
  return path.isAbsolute(location) ? path.resolve(location) : path.resolve(process.cwd(), "prisma", location);
}

function within(child: string, parent: string): boolean {
  const relative = path.relative(parent, child);
  return relative !== "" && !relative.startsWith("..") && !path.isAbsolute(relative);
}

/** Throws unless the database, storage root and master key all belong to one disposable sandbox. */
export function assertSandbox(env: Env = process.env): void {
  const database = sqliteFile(env.DATABASE_URL);
  if (!database) throw new SandboxViolationError("The Security Lab only runs against a SQLite sandbox database");

  const storage = env.STORAGE_ROOT ? path.resolve(env.STORAGE_ROOT) : null;
  const key = env.MASTER_KEY_PATH ? path.resolve(env.MASTER_KEY_PATH) : null;
  if (!storage || !key) {
    throw new SandboxViolationError("The Security Lab needs an explicit sandbox STORAGE_ROOT and MASTER_KEY_PATH");
  }

  // A sandbox run: everything inside one run directory under the lab root.
  const runs = path.join(labRoot(env), "runs");
  if (env.OMNITRUST_SECURITY_LAB === "1" && within(database, runs)) {
    const runDirectory = path.join(runs, path.relative(runs, database).split(path.sep)[0]);
    if (within(storage, runDirectory) && within(key, runDirectory)) return;
    throw new SandboxViolationError("The sandbox database, storage and key must all live in the same run directory");
  }

  // The test suite: the throwaway test database and test storage.
  const testStorage = path.resolve(process.cwd(), "storage", "test");
  if (
    env.VITEST &&
    path.basename(database) === "test.db" &&
    (storage === testStorage || within(storage, testStorage)) &&
    within(key, testStorage)
  ) {
    return;
  }

  throw new SandboxViolationError(
    `Refusing to run an attack scenario against ${database}: it is not a disposable Security Lab sandbox`,
  );
}
