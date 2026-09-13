// Response headers applied to every route by next.config.ts.

/**
 * 'unsafe-inline' on script-src is a known weakening: the Next.js App Router emits inline
 * bootstrap scripts, and removing it needs a per-request nonce pipeline this demonstrator
 * does not implement. React's output escaping remains the primary XSS control. Stated in
 * the README limitations. 'unsafe-eval' and websocket connections are development-only
 * (hot reload).
 */
export function securityHeaders(isDevelopment: boolean): { key: string; value: string }[] {
  const scriptSrc = ["'self'", "'unsafe-inline'", ...(isDevelopment ? ["'unsafe-eval'"] : [])];
  const connectSrc = ["'self'", ...(isDevelopment ? ["ws:"] : [])];

  const contentSecurityPolicy = [
    "default-src 'self'",
    `script-src ${scriptSrc.join(" ")}`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self' data:",
    `connect-src ${connectSrc.join(" ")}`,
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join("; ");

  return [
    { key: "Content-Security-Policy", value: contentSecurityPolicy },
    { key: "X-Frame-Options", value: "DENY" },
    { key: "X-Content-Type-Options", value: "nosniff" },
    { key: "Referrer-Policy", value: "no-referrer" },
    { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), payment=()" },
    { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
  ];
}
