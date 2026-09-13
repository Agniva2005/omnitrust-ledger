import { describe, expect, it } from "vitest";
import { securityHeaders } from "@/lib/http/security-headers";
import nextConfig from "@/next.config";

function header(headers: { key: string; value: string }[], key: string) {
  return headers.find((entry) => entry.key === key)?.value;
}

describe("security headers", () => {
  it("are applied to every route", async () => {
    const rules = await nextConfig.headers!();
    const catchAll = rules.find((rule) => rule.source === "/:path*");
    expect(catchAll).toBeDefined();
    expect(header(catchAll!.headers, "Content-Security-Policy")).toBeTruthy();
  });

  it("forbid framing, plugin content and MIME sniffing", () => {
    const headers = securityHeaders(false);
    const csp = header(headers, "Content-Security-Policy")!;
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("object-src 'none'");
    expect(csp).toContain("base-uri 'self'");
    expect(csp).toContain("form-action 'self'");
    expect(header(headers, "X-Frame-Options")).toBe("DENY");
    expect(header(headers, "X-Content-Type-Options")).toBe("nosniff");
    expect(header(headers, "Referrer-Policy")).toBe("no-referrer");
  });

  it("allow eval and websockets only in development", () => {
    const production = header(securityHeaders(false), "Content-Security-Policy")!;
    const development = header(securityHeaders(true), "Content-Security-Policy")!;
    expect(production).not.toContain("unsafe-eval");
    expect(production).not.toContain("ws:");
    expect(development).toContain("unsafe-eval");
  });

  it("do not advertise the framework", () => {
    expect(nextConfig.poweredByHeader).toBe(false);
  });
});
