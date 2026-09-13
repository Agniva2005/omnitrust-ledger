// Per-worker test environment. Runs before any test module is imported, so the
// PrismaClient in lib/db.ts picks up the test database rather than the dev one.
import fs from "node:fs";
import path from "node:path";

const root = process.cwd();

process.env.DATABASE_URL = "file:./test.db";
process.env.JWT_SECRET = "test-jwt-secret-at-least-32-characters-long";
process.env.STORAGE_ROOT = path.join(root, "storage", "test");
process.env.MASTER_KEY_PATH = path.join(root, "storage", "test", "keys", "master.key");
// The throwaway local chain tests/global-setup.ts starts, on a port apart from `npm run chain`.
process.env.ANCHOR_RPC_URL = "http://127.0.0.1:8546";

fs.mkdirSync(path.join(root, "storage", "test", "documents"), { recursive: true });
fs.mkdirSync(path.join(root, "storage", "test", "keys"), { recursive: true });
