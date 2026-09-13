// CSRF defence in depth for cookie-authenticated state changes, on top of SameSite=Lax.
// Edge-runtime safe: no Node imports.

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

export type OriginVerdict = { allowed: true } | { allowed: false; reason: string };

/**
 * Modern browsers attach Sec-Fetch-Site and Origin to every cross-origin POST, and a page
 * cannot suppress them. A state-changing request is refused if either header says it came
 * from another origin. A request carrying neither header was not sent by a modern
 * browser page, so it is not a CSRF vector and continues to normal authentication.
 */
export function checkRequestOrigin(
  method: string,
  headers: Headers,
  expectedHost: string,
): OriginVerdict {
  if (SAFE_METHODS.has(method.toUpperCase())) return { allowed: true };

  const fetchSite = headers.get("sec-fetch-site");
  if (fetchSite && fetchSite !== "same-origin" && fetchSite !== "none") {
    return { allowed: false, reason: `Sec-Fetch-Site is ${fetchSite}` };
  }

  const origin = headers.get("origin");
  if (origin !== null) {
    let originHost: string | null = null;
    try {
      originHost = new URL(origin).host;
    } catch {
      // "null" (an opaque origin) and malformed values both land here.
    }
    if (originHost !== expectedHost) {
      return { allowed: false, reason: `Origin ${origin} does not match ${expectedHost}` };
    }
  }

  return { allowed: true };
}
