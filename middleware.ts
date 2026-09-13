import { NextResponse, type NextRequest } from "next/server";
import { checkRequestOrigin } from "@/lib/http/origin";

export function middleware(request: NextRequest) {
  const expectedHost = request.headers.get("host") ?? request.nextUrl.host;
  const verdict = checkRequestOrigin(request.method, request.headers, expectedHost);
  if (!verdict.allowed) {
    return NextResponse.json({ error: "Cross-site request refused" }, { status: 403 });
  }
  return NextResponse.next();
}

export const config = { matcher: "/api/:path*" };
