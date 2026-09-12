import { NextResponse } from "next/server";
import { BadRequestError, errorResponse } from "@/lib/api";
import { AuthenticationError } from "@/lib/auth/rbac";
import { getSession } from "@/lib/auth/session";
import { listDocuments, uploadDocument } from "@/lib/documents/service";

export async function GET() {
  try {
    const actor = await getSession();
    if (!actor) throw new AuthenticationError();
    return NextResponse.json({ documents: await listDocuments(actor) });
  } catch (error) {
    return errorResponse(error);
  }
}

export async function POST(request: Request) {
  try {
    const actor = await getSession();
    if (!actor) throw new AuthenticationError();

    const formData = await request.formData().catch(() => null);
    const file = formData?.get("file");
    if (!(file instanceof File)) {
      throw new BadRequestError("Expected a multipart form with a `file` field");
    }

    const document = await uploadDocument({
      actor,
      filename: file.name,
      mimeType: file.type,
      bytes: new Uint8Array(await file.arrayBuffer()),
    });

    return NextResponse.json({ document }, { status: 201 });
  } catch (error) {
    return errorResponse(error);
  }
}
