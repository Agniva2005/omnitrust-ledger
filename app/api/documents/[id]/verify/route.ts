import { NextResponse } from "next/server";
import { BadRequestError, errorResponse } from "@/lib/api";
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

    // An explicit instant re-runs the verifier as at that moment. verifyDocument treats any
    // instant but the present as read-only, so asking cannot publish a revocation list.
    const requestedAt = typeof body?.at === "string" ? new Date(body.at) : undefined;
    if (requestedAt && Number.isNaN(requestedAt.getTime())) throw new BadRequestError("`at` must be an ISO-8601 instant");

    return NextResponse.json({
      result: await verifyDocument(actor, id, {
        versionNumber,
        at: requestedAt,
        // A caller-chosen instant is a hypothetical, so it may not publish a revocation list.
        issueCrlIfStale: requestedAt === undefined,
      }),
    });
  } catch (error) {
    if (error instanceof DocumentNotSignedError) {
      return NextResponse.json({ notSigned: true, error: error.message }, { status: 409 });
    }
    return errorResponse(error);
  }
}
