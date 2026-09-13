import { NextResponse } from "next/server";
import { errorResponse } from "@/lib/api";
import { anchoringOverview } from "@/lib/anchoring/service";
import { AuthenticationError } from "@/lib/auth/rbac";
import { getSession } from "@/lib/auth/session";

export async function GET() {
  try {
    const actor = await getSession();
    if (!actor) throw new AuthenticationError();
    return NextResponse.json(await anchoringOverview(actor));
  } catch (error) {
    return errorResponse(error);
  }
}
