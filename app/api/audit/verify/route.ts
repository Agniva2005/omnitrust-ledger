import { NextResponse } from "next/server";
import { errorResponse } from "@/lib/api";
import { verifyAuditChain } from "@/lib/audit/integrity";
import { AuthenticationError, requireCapability } from "@/lib/auth/rbac";
import { getSession } from "@/lib/auth/session";

export async function POST() {
  try {
    const actor = await getSession();
    if (!actor) throw new AuthenticationError();
    requireCapability(actor, "audit:verify");

    return NextResponse.json({ result: await verifyAuditChain() });
  } catch (error) {
    return errorResponse(error);
  }
}
