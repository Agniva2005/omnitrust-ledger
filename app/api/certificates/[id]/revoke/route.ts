import { NextResponse } from "next/server";
import { z } from "zod";
import { errorResponse } from "@/lib/api";
import { AuthenticationError } from "@/lib/auth/rbac";
import { getSession } from "@/lib/auth/session";
import { revokeCertificate } from "@/lib/pki/certificates";
import { REVOCATION_REASONS } from "@/lib/pki/revocation";

const schema = z.object({
  reason: z.enum(REVOCATION_REASONS).optional(),
  invalidityDate: z.string().datetime({ offset: true }).optional(),
  comment: z.string().max(200).optional(),
});

export async function POST(request: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const actor = await getSession();
    if (!actor) throw new AuthenticationError();

    const parsed = schema.safeParse((await request.json().catch(() => ({}))) ?? {});
    if (!parsed.success) {
      return NextResponse.json(
        {
          error: `reason must be one of: ${REVOCATION_REASONS.join(", ")}; invalidityDate must be an ISO 8601 date-time`,
        },
        { status: 400 },
      );
    }

    const { id } = await params;
    const certificate = await revokeCertificate({
      actor,
      certificateId: id,
      reason: parsed.data.reason,
      invalidityDate: parsed.data.invalidityDate ? new Date(parsed.data.invalidityDate) : undefined,
      comment: parsed.data.comment,
    });

    return NextResponse.json({ certificate });
  } catch (error) {
    return errorResponse(error);
  }
}
