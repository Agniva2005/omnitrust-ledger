import { NextResponse } from "next/server";
import { BadRequestError, errorResponse } from "@/lib/api";
import { AuthenticationError } from "@/lib/auth/rbac";
import { getSession } from "@/lib/auth/session";
import { addDocumentVersion } from "@/lib/documents/service";

export async function POST(request: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const actor = await getSession();
    if (!actor) throw new AuthenticationError();

    const formData = await request.formData().catch(() => null);
    const file = formData?.get("file");
    if (!(file instanceof File)) {
      throw new BadRequestError("Expected a multipart form with a `file` field");
    }

    const { id } = await params;
    const document = await addDocumentVersion(
      actor,
      id,
      file.name,
      new Uint8Array(await file.arrayBuffer()),
    );

    return NextResponse.json({ document }, { status: 201 });
  } catch (error) {
    return errorResponse(error);
  }
}
