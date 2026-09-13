import { NextResponse } from "next/server";
import { redactErrorForLog } from "@/lib/api";
import { appendAuditEntry } from "@/lib/audit/log";
import { clearedSessionCookie, getSession } from "@/lib/auth/session";

export async function POST() {
  try {
    const actor = await getSession();
    if (actor) {
      await appendAuditEntry({
        actorUserId: actor.userId,
        action: "USER_LOGOUT",
        targetType: "User",
        targetId: actor.userId,
        metadata: { email: actor.email },
      });
    }
  } catch (error) {
    // Signing out must always clear the cookie, even if the audit write fails.
    console.error("Logout audit failed", redactErrorForLog(error));
  }

  const response = NextResponse.json({ ok: true });
  response.cookies.set(clearedSessionCookie());
  return response;
}
