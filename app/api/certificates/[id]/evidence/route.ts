import { errorResponse } from "@/lib/api";
import { AuthenticationError } from "@/lib/auth/rbac";
import { getSession } from "@/lib/auth/session";
import { buildCertificatePack } from "@/lib/evidence/certificate-pack";

/** GET: the certificate, its issuer, the current CRL and the explorer's checks, as a ZIP. */
export async function GET(_request: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const actor = await getSession();
    if (!actor) throw new AuthenticationError();

    const { id } = await params;
    const pack = await buildCertificatePack(actor, id);
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
