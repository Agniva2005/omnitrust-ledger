import { NextResponse } from "next/server";
import { errorResponse } from "@/lib/api";
import { AuthenticationError } from "@/lib/auth/rbac";
import { getSession } from "@/lib/auth/session";
import { listScenarios, runSecurityLab } from "@/lib/security-lab/service";

export const maxDuration = 300;

/** GET: the attack scenarios (ADMIN). */
export async function GET() {
  try {
    const actor = await getSession();
    if (!actor) throw new AuthenticationError();
    return NextResponse.json({ scenarios: listScenarios(actor) });
  } catch (error) {
    return errorResponse(error);
  }
}

/** POST {scenario}: runs one scenario in a disposable sandbox (ADMIN). */
export async function POST(request: Request) {
  try {
    const actor = await getSession();
    if (!actor) throw new AuthenticationError();
    const body = (await request.json().catch(() => null)) as { scenario?: unknown } | null;
    return NextResponse.json({ run: await runSecurityLab(actor, body?.scenario) });
  } catch (error) {
    return errorResponse(error);
  }
}
