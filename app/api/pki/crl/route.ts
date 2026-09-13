import { NextResponse } from "next/server";
import { NotFoundError, errorResponse } from "@/lib/api";
import { crlPem, latestCrl } from "@/lib/pki/crl";

/**
 * The local CA's newest certificate revocation list. Public and unauthenticated, as revocation
 * lists are meant to be: they are signed by the CA, so a copy obtained from anywhere can be
 * checked independently. DER by default; `?format=pem` for PEM.
 *
 * Read-only: an unauthenticated GET never makes the CA sign. Lists are issued on revocation and
 * when an authenticated verification needs a current one. A lapsed list is served as it is; its
 * nextUpdate tells the consumer it is stale.
 */
export async function GET(request: Request) {
  try {
    const list = await latestCrl();
    if (!list) throw new NotFoundError("No revocation list has been issued yet");
    const filename = `omnitrust-root-ca-crl-${list.crlNumber}`;
    const common = { "X-CRL-Next-Update": list.nextUpdate.toISOString(), "Cache-Control": "no-store" };

    if (new URL(request.url).searchParams.get("format") === "pem") {
      return new NextResponse(crlPem(list), {
        headers: {
          ...common,
          "Content-Type": "application/x-pem-file",
          "Content-Disposition": `attachment; filename="${filename}.pem"`,
        },
      });
    }

    return new NextResponse(new Uint8Array(list.der), {
      headers: {
        ...common,
        "Content-Type": "application/pkix-crl",
        "Content-Disposition": `attachment; filename="${filename}.crl"`,
      },
    });
  } catch (error) {
    return errorResponse(error);
  }
}
