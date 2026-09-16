import { NextResponse } from "next/server";
import { errorResponse } from "@/lib/api";
import { AuthenticationError } from "@/lib/auth/rbac";
import { getSession } from "@/lib/auth/session";
import { DocumentNotSignedError, verifyDocument } from "@/lib/documents/verification";

export async function POST(request: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const actor = await getSession();
    if (!actor) throw new AuthenticationError();

    const { id } = await params;
    const body = await request.json().catch(() => ({}));
    const versionNumber = Number.isInteger(body?.version) ? (body.version as number) : undefined;
    return NextResponse.json({ result: await verifyDocument(actor, id, { versionNumber }) });
  } catch (error) {
    if (error instanceof DocumentNotSignedError) {
      return NextResponse.json({ notSigned: true, error: error.message }, { status: 409 });
    }
    return errorResponse(error);
  }
}
