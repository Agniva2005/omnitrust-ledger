import { NextResponse } from "next/server";
import { BadRequestError, errorResponse } from "@/lib/api";
import { ANCHOR_KINDS, isAnchorKind, verifyAnchorAs } from "@/lib/anchoring/service";
import { AuthenticationError } from "@/lib/auth/rbac";
import { getSession } from "@/lib/auth/session";

/** GET ?kind=SIGNATURE|AUDIT_CHECKPOINT&target=<id>: the item's anchor, proof and on-chain status. */
export async function GET(request: Request) {
  try {
    const actor = await getSession();
    if (!actor) throw new AuthenticationError();

    const url = new URL(request.url);
    const kind = url.searchParams.get("kind");
    const target = url.searchParams.get("target");
    if (!isAnchorKind(kind)) throw new BadRequestError(`kind must be one of: ${ANCHOR_KINDS.join(", ")}`);
    if (!target || target.length > 64) throw new BadRequestError("target must be an item id");

    return NextResponse.json({ result: await verifyAnchorAs(actor, kind, target) });
  } catch (error) {
    return errorResponse(error);
  }
}
