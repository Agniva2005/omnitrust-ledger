import { NextResponse } from "next/server";
import { BadRequestError, errorResponse } from "@/lib/api";
import { nodeStatus, startLocalChain, stopLocalChain } from "@/lib/anchoring/local-node";
import { AuthenticationError } from "@/lib/auth/rbac";
import { getSession } from "@/lib/auth/session";

export const maxDuration = 60;

/** GET: whether a chain is answering, and whether this application started it. */
export async function GET() {
  try {
    const actor = await getSession();
    if (!actor) throw new AuthenticationError();
    return NextResponse.json({ node: await nodeStatus() });
  } catch (error) {
    return errorResponse(error);
  }
}

/** POST {action: "start" | "stop"}: runs the local development chain (ADMIN). */
export async function POST(request: Request) {
  try {
    const actor = await getSession();
    if (!actor) throw new AuthenticationError();

    const body = (await request.json().catch(() => ({}))) as { action?: unknown };
    if (body.action === "start") return NextResponse.json({ node: await startLocalChain(actor) });
    if (body.action === "stop") return NextResponse.json({ node: await stopLocalChain(actor) });
    throw new BadRequestError("Expected action to be one of: start, stop");
  } catch (error) {
    return errorResponse(error);
  }
}
