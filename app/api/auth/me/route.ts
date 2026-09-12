import { NextResponse } from "next/server";
import { capabilitiesFor } from "@/lib/auth/rbac";
import { getSession } from "@/lib/auth/session";

export async function GET() {
  const actor = await getSession();
  if (!actor) return NextResponse.json({ user: null }, { status: 401 });
  return NextResponse.json({
    user: { id: actor.userId, email: actor.email, role: actor.role },
    capabilities: capabilitiesFor(actor.role),
  });
}
