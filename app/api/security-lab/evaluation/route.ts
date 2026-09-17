import { errorResponse } from "@/lib/api";
import { AuthenticationError } from "@/lib/auth/rbac";
import { getSession } from "@/lib/auth/session";
import { buildEvaluationPack } from "@/lib/evidence/evaluation-pack";

/** GET: the adversarial evaluation matrix and the threat model's adversary list, as a ZIP. */
export async function GET() {
  try {
    const actor = await getSession();
    if (!actor) throw new AuthenticationError();

    const pack = await buildEvaluationPack(actor);
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
