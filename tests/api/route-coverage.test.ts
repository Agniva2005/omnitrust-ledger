// Every API route must be exercised at the route level by some test, not only through its
// service function: the handler is where session lookup, input validation, status mapping and
// response shaping happen. This test fails when a route is added without a test that imports it.
import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const ROOT = process.cwd();

function filesUnder(directory: string, predicate: (file: string) => boolean): string[] {
  const found: string[] = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) found.push(...filesUnder(full, predicate));
    else if (predicate(full)) found.push(full);
  }
  return found;
}

describe("route-level test coverage", () => {
  it("has a test importing every app/api route handler", () => {
    const routes = filesUnder(path.join(ROOT, "app", "api"), (file) => path.basename(file) === "route.ts").map(
      (file) => `@/${path.relative(ROOT, file).split(path.sep).join("/").replace(/\.ts$/, "")}`,
    );
    const tests = filesUnder(path.join(ROOT, "tests"), (file) => file.endsWith(".test.ts"))
      .map((file) => fs.readFileSync(file, "utf8"))
      .join("\n");

    expect(routes.length).toBeGreaterThan(20);
    const untested = routes.filter((route) => !tests.includes(`"${route}"`));
    expect(untested, `routes without a route-level test: ${untested.join(", ")}`).toEqual([]);
  });
});
