import { errorResponse } from "@/lib/api";
import { AuthenticationError } from "@/lib/auth/rbac";
import { getSession } from "@/lib/auth/session";
import { buildEvidencePack } from "@/lib/evidence/pack";

/** GET ?version=N: the evidence pack for a signed version, as a ZIP. */
export async function GET(request: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const actor = await getSession();
    if (!actor) throw new AuthenticationError();

    const { id } = await params;
    const requested = Number.parseInt(new URL(request.url).searchParams.get("version") ?? "", 10);
    const pack = await buildEvidencePack(actor, id, Number.isInteger(requested) ? requested : undefined);

    return new Response(new Uint8Array(pack.bytes), {
      headers: {
        "Content-Type": "application/zip",
        "Content-Disposition": `attachment; filename="${pack.filename}"`,
        "Content-Length": String(pack.bytes.length),
      },
    });
  } catch (error) {
    return errorResponse(error);
  }
}
