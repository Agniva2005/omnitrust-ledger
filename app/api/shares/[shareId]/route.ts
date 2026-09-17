import { NextResponse } from "next/server";
import { errorResponse } from "@/lib/api";
import { AuthenticationError } from "@/lib/auth/rbac";
import { getSession } from "@/lib/auth/session";
import { revokeShare } from "@/lib/documents/sharing";

/** DELETE: withdraws a share. Checked on every later access, so it takes effect at once. */
export async function DELETE(_request: Request, { params }: { params: Promise<{ shareId: string }> }) {
  try {
    const actor = await getSession();
    if (!actor) throw new AuthenticationError();
    const { shareId } = await params;
    return NextResponse.json({ share: await revokeShare(actor, shareId) });
  } catch (error) {
    return errorResponse(error);
  }
}
