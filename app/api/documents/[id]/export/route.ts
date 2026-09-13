import { NextResponse } from "next/server";
import { BadRequestError, errorResponse } from "@/lib/api";
import { AuthenticationError } from "@/lib/auth/rbac";
import { getSession } from "@/lib/auth/session";
import { EXPORT_PARTS, exportSignedDocument, isExportPart } from "@/lib/documents/export";

/** GET ?part=cms|content|certificate[&version=n]: a file for verification outside this app. */
export async function GET(request: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const actor = await getSession();
    if (!actor) throw new AuthenticationError();

    const url = new URL(request.url);
    const part = url.searchParams.get("part") ?? "cms";
    if (!isExportPart(part)) {
      throw new BadRequestError(`part must be one of: ${EXPORT_PARTS.join(", ")}`);
    }

    const versionParam = url.searchParams.get("version");
    const versionNumber = versionParam === null ? undefined : Number(versionParam);
    if (versionNumber !== undefined && (!Number.isInteger(versionNumber) || versionNumber < 1)) {
      throw new BadRequestError("version must be a positive integer");
    }

    const { id } = await params;
    const file = await exportSignedDocument(actor, id, part, versionNumber);

    return new NextResponse(new Uint8Array(file.bytes), {
      headers: {
        "Content-Type": file.contentType,
        "Content-Disposition": `attachment; filename="${file.filename}"`,
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
      },
    });
  } catch (error) {
    return errorResponse(error);
  }
}
