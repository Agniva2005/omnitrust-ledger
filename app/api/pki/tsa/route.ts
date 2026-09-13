import { NextResponse } from "next/server";
import { NotFoundError, errorResponse } from "@/lib/api";
import { activeTimestampAuthority } from "@/lib/pki/tsa";

/**
 * The local Time-Stamp Authority's certificate, which an external tool needs alongside the CA
 * certificate to check a time-stamp token that does not embed it. Public: a certificate is not
 * secret. Trusted by nothing outside this installation.
 *
 * Read-only: an unauthenticated GET never creates the authority (that would generate a key and
 * write to the database). The authority is created on the first authenticated time-stamp.
 */
export async function GET() {
  try {
    const authority = await activeTimestampAuthority();
    if (!authority) throw new NotFoundError("The Time-Stamp Authority has not been created yet");
    return new NextResponse(authority.certPem, {
      headers: {
        "Content-Type": "application/x-pem-file",
        "Content-Disposition": 'attachment; filename="omnitrust-tsa.pem"',
      },
    });
  } catch (error) {
    return errorResponse(error);
  }
}
