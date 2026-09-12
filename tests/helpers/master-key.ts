import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { resetMasterKeyCache } from "@/lib/crypto/symmetric";

/** Creates the test master key that tests/setup.ts points MASTER_KEY_PATH at. */
export function ensureMasterKey() {
  const keyPath = process.env.MASTER_KEY_PATH!;
  fs.mkdirSync(path.dirname(keyPath), { recursive: true });
  if (!fs.existsSync(keyPath)) {
    fs.writeFileSync(keyPath, crypto.randomBytes(32).toString("base64"));
  }
  resetMasterKeyCache();
  return keyPath;
}
