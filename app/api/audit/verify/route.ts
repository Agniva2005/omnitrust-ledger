import { NextResponse } from "next/server";
import { errorResponse } from "@/lib/api";
import { AuthenticationError } from "@/lib/auth/rbac";
import { getSession } from "@/lib/auth/session";
import { verifyAuditLogAs } from "@/lib/pki/audit-checkpoints";

export async function POST() {
  try {
    const actor = await getSession();
    if (!actor) throw new AuthenticationError();
    return NextResponse.json({ result: await verifyAuditLogAs(actor) });
  } catch (error) {
    return errorResponse(error);
  }
}
