import { errorResponse } from "@/lib/api";
import { AuthenticationError } from "@/lib/auth/rbac";
import { getSession } from "@/lib/auth/session";
import { buildAuditPack } from "@/lib/evidence/audit-pack";

/** GET: the whole audit log, its checkpoints and the integrity walk, as a ZIP. */
export async function GET() {
  try {
    const actor = await getSession();
    if (!actor) throw new AuthenticationError();

    const pack = await buildAuditPack(actor);
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
