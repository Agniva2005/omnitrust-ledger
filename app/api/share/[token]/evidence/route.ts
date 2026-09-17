import { errorResponse } from "@/lib/api";
import { ShareUnavailableError, openShare } from "@/lib/documents/sharing";
import { buildEvidencePack } from "@/lib/evidence/pack";

/**
 * The evidence pack for a shared version, for a visitor with no account. The token is the
 * authorisation, and openShare re-checks expiry and withdrawal on every call.
 */
export async function GET(_request: Request, { params }: { params: Promise<{ token: string }> }) {
  try {
    const { token } = await params;
    const share = await openShare(token);
    const pack = await buildEvidencePack(null, share.documentId, share.versionNumber);

    return new Response(new Uint8Array(pack.bytes), {
      headers: {
        "Content-Type": "application/zip",
        "Content-Disposition": `attachment; filename="${pack.filename}"`,
        "Content-Length": String(pack.bytes.length),
      },
    });
  } catch (error) {
    if (error instanceof ShareUnavailableError) {
      return new Response(error.message, { status: 404 });
    }
    return errorResponse(error);
  }
}
