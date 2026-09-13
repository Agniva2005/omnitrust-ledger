import { NextResponse } from "next/server";
import { errorResponse } from "@/lib/api";
import { AuthenticationError } from "@/lib/auth/rbac";
import { getSession } from "@/lib/auth/session";
import { respondToTimestampRequest } from "@/lib/pki/tsa";

const MAX_REQUEST_BYTES = 8192;

/**
 * RFC 3161 over HTTP (section 3.4): a DER TimeStampReq in, a DER TimeStampResp out.
 * Requires a signed-in account, so this demonstrator does not operate an open time-stamping
 * service. Works with `openssl ts -query` given the session cookie.
 */
export async function POST(request: Request) {
  try {
    const actor = await getSession();
    if (!actor) throw new AuthenticationError();

    if (request.headers.get("content-type") !== "application/timestamp-query") {
      return NextResponse.json(
        { error: "Content-Type must be application/timestamp-query" },
        { status: 415 },
      );
    }

    const body = new Uint8Array(await request.arrayBuffer());
    if (body.byteLength === 0 || body.byteLength > MAX_REQUEST_BYTES) {
      return NextResponse.json({ error: "Time-stamp request size is out of range" }, { status: 400 });
    }

    const response = await respondToTimestampRequest(body);
    return new NextResponse(new Uint8Array(response), {
      headers: { "Content-Type": "application/timestamp-reply" },
    });
  } catch (error) {
    return errorResponse(error);
  }
}
