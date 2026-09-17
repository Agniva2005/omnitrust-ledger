import { NextResponse } from "next/server";
import { BadRequestError, errorResponse } from "@/lib/api";
import { AuthenticationError } from "@/lib/auth/rbac";
import { getSession } from "@/lib/auth/session";
import { createShare, listShares } from "@/lib/documents/sharing";

/** GET: the shares on this document, for its holder's own trail. */
export async function GET(_request: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const actor = await getSession();
    if (!actor) throw new AuthenticationError();
    const { id } = await params;
    return NextResponse.json({ shares: await listShares(actor, id) });
  } catch (error) {
    return errorResponse(error);
  }
}

/** POST {audience, note?, days?, version?}: mints a link. The token is returned once only. */
export async function POST(request: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const actor = await getSession();
    if (!actor) throw new AuthenticationError();

    const body = (await request.json().catch(() => ({}))) as Record<string, unknown>;
    if (typeof body.audience !== "string") throw new BadRequestError("Say who this is being shared with");

    const { id } = await params;
    const created = await createShare(actor, id, {
      audience: body.audience,
      note: typeof body.note === "string" ? body.note : undefined,
      days: Number.isInteger(body.days) ? (body.days as number) : undefined,
      versionNumber: Number.isInteger(body.version) ? (body.version as number) : undefined,
    });
    return NextResponse.json(created, { status: 201 });
  } catch (error) {
    return errorResponse(error);
  }
}
