import { NextResponse } from "next/server";
import { errorResponse } from "@/lib/api";
import { requireRole } from "@/lib/auth/rbac";
import { getSession } from "@/lib/auth/session";

/** Diagnostic endpoint: the smallest possible ADMIN-only route, used by the RBAC tests. */
export async function GET() {
  try {
    const actor = requireRole(await getSession(), ["ADMIN"]);
    return NextResponse.json({ ok: true, role: actor.role });
  } catch (error) {
    return errorResponse(error);
  }
}
