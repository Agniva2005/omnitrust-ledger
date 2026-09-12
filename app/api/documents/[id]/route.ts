import { NextResponse } from "next/server";
import { errorResponse } from "@/lib/api";
import { AuthenticationError } from "@/lib/auth/rbac";
import { getSession } from "@/lib/auth/session";
import { getDocument } from "@/lib/documents/service";

export async function GET(_request: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const actor = await getSession();
    if (!actor) throw new AuthenticationError();
    const { id } = await params;
    return NextResponse.json({ document: await getDocument(actor, id) });
  } catch (error) {
    return errorResponse(error);
  }
}
