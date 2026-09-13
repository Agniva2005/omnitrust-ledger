import { NextResponse } from "next/server";
import { errorResponse } from "@/lib/api";
import { crlPem, currentCrl } from "@/lib/pki/crl";

/**
 * The local CA's current certificate revocation list. Public and unauthenticated, as
 * revocation lists are meant to be: they are signed by the CA, so a copy obtained from
 * anywhere can be checked independently. DER by default; `?format=pem` for PEM.
 */
export async function GET(request: Request) {
  try {
    const list = await currentCrl();
    const filename = `omnitrust-root-ca-crl-${list.crlNumber}`;

    if (new URL(request.url).searchParams.get("format") === "pem") {
      return new NextResponse(crlPem(list), {
        headers: {
          "Content-Type": "application/x-pem-file",
          "Content-Disposition": `attachment; filename="${filename}.pem"`,
        },
      });
    }

    return new NextResponse(new Uint8Array(list.der), {
      headers: {
        "Content-Type": "application/pkix-crl",
        "Content-Disposition": `attachment; filename="${filename}.crl"`,
      },
    });
  } catch (error) {
    return errorResponse(error);
  }
}
