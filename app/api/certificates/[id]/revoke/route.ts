import { NextResponse } from "next/server";
import { z } from "zod";
import { errorResponse } from "@/lib/api";
import { AuthenticationError } from "@/lib/auth/rbac";
import { getSession } from "@/lib/auth/session";
import { revokeCertificate } from "@/lib/pki/certificates";

const schema = z.object({ reason: z.string().max(200).optional() });

export async function POST(request: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const actor = await getSession();
    if (!actor) throw new AuthenticationError();

    const body = await request.json().catch(() => ({}));
    const parsed = schema.safeParse(body ?? {});
    const { id } = await params;

    const certificate = await revokeCertificate({
      actor,
      certificateId: id,
      reason: parsed.success ? parsed.data.reason : undefined,
    });

    return NextResponse.json({ certificate });
  } catch (error) {
    return errorResponse(error);
  }
}
