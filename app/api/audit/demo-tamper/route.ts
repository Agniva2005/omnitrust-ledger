import { NextResponse } from "next/server";
import { BadRequestError, errorResponse } from "@/lib/api";
import {
  auditTamperState,
  deleteAuditEntry,
  restoreAuditLog,
  rewriteAuditChain,
  tamperAuditEntry,
} from "@/lib/audit/demo-tamper";
import { AuthenticationError } from "@/lib/auth/rbac";
import { getSession } from "@/lib/auth/session";

export async function GET() {
  try {
    const actor = await getSession();
    if (!actor) throw new AuthenticationError();
    return NextResponse.json({ state: await auditTamperState() });
  } catch (error) {
    return errorResponse(error);
  }
}

/** POST {action, seq?, replacement?}: alters the real audit log, or puts it back (ADMIN). */
export async function POST(request: Request) {
  try {
    const actor = await getSession();
    if (!actor) throw new AuthenticationError();

    const body = (await request.json().catch(() => ({}))) as { action?: unknown; seq?: unknown; replacement?: unknown };
    const replacement = typeof body.replacement === "string" && body.replacement.length > 0 ? body.replacement : "edited by an attacker";

    if (body.action === "restore") {
      return NextResponse.json({ state: await restoreAuditLog(actor) });
    }

    if (!Number.isInteger(body.seq)) throw new BadRequestError("Expected `seq` to be the sequence number of an entry");
    const seq = body.seq as number;

    switch (body.action) {
      case "edit":
        return NextResponse.json({ state: await tamperAuditEntry(actor, seq, replacement) });
      case "delete":
        return NextResponse.json({ state: await deleteAuditEntry(actor, seq) });
      case "rewrite":
        return NextResponse.json({ state: await rewriteAuditChain(actor, seq, replacement) });
      default:
        throw new BadRequestError("Expected action to be one of: edit, delete, rewrite, restore");
    }
  } catch (error) {
    return errorResponse(error);
  }
}
