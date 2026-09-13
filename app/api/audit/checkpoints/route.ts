import { NextResponse } from "next/server";
import { errorResponse } from "@/lib/api";
import { AuthenticationError, requireCapability } from "@/lib/auth/rbac";
import { getSession } from "@/lib/auth/session";
import { createAuditCheckpoint, listAuditCheckpoints } from "@/lib/pki/audit-checkpoints";

export async function GET() {
  try {
    const actor = await getSession();
    if (!actor) throw new AuthenticationError();
    requireCapability(actor, "audit:read");
    return NextResponse.json({ checkpoints: await listAuditCheckpoints() });
  } catch (error) {
    return errorResponse(error);
  }
}

export async function POST() {
  try {
    const actor = await getSession();
    if (!actor) throw new AuthenticationError();
    const checkpoint = await createAuditCheckpoint(actor);
    return NextResponse.json(
      {
        checkpoint: {
          id: checkpoint.id,
          seq: checkpoint.seq,
          entryHash: checkpoint.entryHash,
          checkpointHash: checkpoint.checkpointHash,
          createdAt: checkpoint.createdAt,
          timestamped: checkpoint.timestampToken !== null,
        },
      },
      { status: 201 },
    );
  } catch (error) {
    return errorResponse(error);
  }
}
