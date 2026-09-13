import { NextResponse } from "next/server";
import { errorResponse } from "@/lib/api";
import { getRootCa } from "@/lib/pki/ca";

/**
 * The local root CA certificate, the trust anchor an external tool needs to check this
 * installation's certificates, CRLs and time-stamps. Public: a CA certificate is not secret.
 * It is trusted by nothing outside this installation.
 */
export async function GET() {
  try {
    const ca = await getRootCa();
    return new NextResponse(ca.certPem, {
      headers: {
        "Content-Type": "application/x-pem-file",
        "Content-Disposition": 'attachment; filename="omnitrust-root-ca.pem"',
      },
    });
  } catch (error) {
    return errorResponse(error);
  }
}
