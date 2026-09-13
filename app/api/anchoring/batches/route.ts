import { NextResponse } from "next/server";
import { errorResponse } from "@/lib/api";
import { anchorPending } from "@/lib/anchoring/service";
import { AuthenticationError } from "@/lib/auth/rbac";
import { getSession } from "@/lib/auth/session";

/** Anchors every pending commitment as one Merkle root (ADMIN). */
export async function POST() {
  try {
    const actor = await getSession();
    if (!actor) throw new AuthenticationError();
    const batch = await anchorPending(actor);
    return NextResponse.json(
      {
        batch: {
          id: batch.id,
          root: batch.root,
          leafCount: batch.leafCount,
          txHash: batch.txHash,
          blockNumber: batch.blockNumber,
          blockTimestamp: batch.blockTimestamp,
        },
      },
      { status: 201 },
    );
  } catch (error) {
    return errorResponse(error);
  }
}
