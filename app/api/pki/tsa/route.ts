import { NextResponse } from "next/server";
import { errorResponse } from "@/lib/api";
import { ensureTimestampAuthority } from "@/lib/pki/tsa";

/**
 * The local Time-Stamp Authority's certificate, which an external tool needs alongside the
 * CA certificate to check a time-stamp token that does not embed it. Public: a certificate
 * is not secret. Trusted by nothing outside this installation.
 */
export async function GET() {
  try {
    const authority = await ensureTimestampAuthority();
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
