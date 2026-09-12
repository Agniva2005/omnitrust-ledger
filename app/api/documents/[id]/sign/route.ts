import { NextResponse } from "next/server";
import { z } from "zod";
import { errorResponse } from "@/lib/api";
import { AuthenticationError } from "@/lib/auth/rbac";
import { getSession } from "@/lib/auth/session";
import { signDocument } from "@/lib/documents/signing";

const schema = z.object({ certificateId: z.string().min(1) });

export async function POST(request: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const actor = await getSession();
    if (!actor) throw new AuthenticationError();

    const parsed = schema.safeParse(await request.json().catch(() => null));
    if (!parsed.success) {
      return NextResponse.json({ error: "certificateId is required" }, { status: 400 });
    }

    const { id } = await params;
    const result = await signDocument({
      actor,
      documentId: id,
      certificateId: parsed.data.certificateId,
    });

    return NextResponse.json(
      {
        signature: {
          id: result.signature.id,
          algorithm: result.signature.algorithm,
          signatureBytes: Buffer.from(result.signature.signatureBytes).toString("base64"),
          signatureByteLength: result.signature.signatureBytes.length,
          signedAt: result.signature.signedAt,
        },
        signedHash: result.signedHash,
        documentStatus: result.documentStatus,
      },
      { status: 201 },
    );
  } catch (error) {
    return errorResponse(error);
  }
}
