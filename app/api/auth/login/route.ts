import { NextResponse } from "next/server";
import { z } from "zod";
import { errorResponse, TooManyRequestsError } from "@/lib/api";
import { appendAuditEntry } from "@/lib/audit/log";
import { accountKey, clientKey, loginRateLimit } from "@/lib/auth/rate-limit";
import { authenticate, createSessionToken, sessionCookie } from "@/lib/auth/session";

// Not z.string().email(): the demo accounts named in CLAUDE.md Section 5 Phase 9
// (signer@demo and friends) are not RFC-valid addresses, having no TLD. The field
// is an opaque account identifier resolved by exact match, so it is length-bounded
// rather than format-checked.
const schema = z.object({
  email: z.string().min(3).max(254),
  password: z.string().min(1).max(200),
});

export async function POST(request: Request) {
  try {
    const parsed = schema.safeParse(await request.json().catch(() => null));
    if (!parsed.success) {
      return NextResponse.json({ error: "Email and password are required" }, { status: 400 });
    }

    const account = accountKey(parsed.data.email);
    const client = clientKey(request);

    // Checked before the password, so a locked account costs no bcrypt work and a
    // correct password cannot be confirmed while the lock is in force.
    const retryAfter = loginRateLimit.retryAfterSeconds(account, client);
    if (retryAfter > 0) {
      await appendAuditEntry({
        action: "USER_LOGIN_THROTTLED",
        targetType: "User",
        targetId: account,
        metadata: { attemptedEmail: account, retryAfterSeconds: retryAfter },
      });
      throw new TooManyRequestsError(
        "Too many failed sign-in attempts. Try again later.",
        retryAfter,
      );
    }

    const actor = await authenticate(parsed.data.email, parsed.data.password);
    if (!actor) {
      loginRateLimit.recordFailure(account, client);
      // The attempted identifier is recorded; the submitted password never is.
      await appendAuditEntry({
        action: "USER_LOGIN_FAILED",
        targetType: "User",
        targetId: account,
        metadata: { attemptedEmail: account },
      });
      return NextResponse.json({ error: "Invalid email or password" }, { status: 401 });
    }

    loginRateLimit.recordSuccess(account);

    await appendAuditEntry({
      actorUserId: actor.userId,
      action: "USER_LOGIN",
      targetType: "User",
      targetId: actor.userId,
      metadata: { email: actor.email, role: actor.role },
    });

    const response = NextResponse.json({
      user: { id: actor.userId, email: actor.email, role: actor.role },
    });
    response.cookies.set(sessionCookie(await createSessionToken(actor)));
    return response;
  } catch (error) {
    return errorResponse(error);
  }
}
