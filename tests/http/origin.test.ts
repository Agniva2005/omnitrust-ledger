import { NextRequest } from "next/server";
import { describe, expect, it } from "vitest";
import { checkRequestOrigin } from "@/lib/http/origin";
import { middleware } from "@/middleware";

const HOST = "localhost:3000";
const allowed = (method: string, headers: Record<string, string>) =>
  checkRequestOrigin(method, new Headers(headers), HOST).allowed;

describe("checkRequestOrigin", () => {
  it("allows safe methods whatever their origin", () => {
    expect(allowed("GET", { origin: "https://evil.example", "sec-fetch-site": "cross-site" })).toBe(
      true,
    );
  });

  it("allows a same-origin browser POST", () => {
    expect(allowed("POST", { origin: `http://${HOST}`, "sec-fetch-site": "same-origin" })).toBe(true);
  });

  it("refuses a POST the browser marks as cross-site", () => {
    expect(allowed("POST", { "sec-fetch-site": "cross-site" })).toBe(false);
  });

  it("refuses a same-site but cross-origin POST, such as from a sibling subdomain", () => {
    expect(allowed("POST", { "sec-fetch-site": "same-site" })).toBe(false);
  });

  it("refuses a POST whose Origin names another host", () => {
    expect(allowed("POST", { origin: "https://evil.example" })).toBe(false);
  });

  it("refuses an Origin on the same host name but a different port", () => {
    expect(allowed("DELETE", { origin: "http://localhost:4000" })).toBe(false);
  });

  it("refuses an opaque origin, as sent from sandboxed frames and some redirects", () => {
    expect(allowed("POST", { origin: "null" })).toBe(false);
  });

  it("allows a request with neither header, which a modern browser page cannot send", () => {
    expect(allowed("POST", {})).toBe(true);
  });
});

describe("middleware on /api routes", () => {
  it("returns 403 for a cross-site POST", async () => {
    const response = middleware(
      new NextRequest(`http://${HOST}/api/documents`, {
        method: "POST",
        headers: { origin: "https://evil.example" },
      }),
    );
    expect(response.status).toBe(403);
    expect(await response.json()).toEqual({ error: "Cross-site request refused" });
  });

  it("passes a same-origin POST through to the route", () => {
    const response = middleware(
      new NextRequest(`http://${HOST}/api/documents`, {
        method: "POST",
        headers: { origin: `http://${HOST}`, "sec-fetch-site": "same-origin" },
      }),
    );
    expect(response.headers.get("x-middleware-next")).toBe("1");
  });
});
