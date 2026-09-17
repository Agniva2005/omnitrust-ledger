import { NextResponse } from "next/server";
import { BadRequestError, errorResponse } from "@/lib/api";
import { AuthenticationError } from "@/lib/auth/rbac";
import { getSession } from "@/lib/auth/session";
import {
  restoreTamper,
  tamperAlgorithmLabel,
  tamperCiphertext,
  tamperContent,
  tamperKeySubstitution,
  tamperReplay,
  tamperSignature,
  tamperState,
  tamperTimestampSwap,
} from "@/lib/documents/demo-tamper";

export async function GET(_request: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const actor = await getSession();
    if (!actor) throw new AuthenticationError();

    const { id } = await params;
    return NextResponse.json({ state: await tamperState(id) });
  } catch (error) {
    return errorResponse(error);
  }
}

export async function POST(request: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const actor = await getSession();
    if (!actor) throw new AuthenticationError();
    const { id } = await params;

    // The content replacement carries a file, so it arrives as multipart; the rest are plain JSON.
    if (request.headers.get("content-type")?.includes("multipart/form-data")) {
      const formData = await request.formData().catch(() => null);
      const file = formData?.get("file");
      if (!(file instanceof File)) {
        throw new BadRequestError("Expected a multipart form with a `file` field");
      }
      const state = await tamperContent(actor, id, new Uint8Array(await file.arrayBuffer()));
      return NextResponse.json({ state });
    }

    const body = await request.json().catch(() => ({}));
    switch (body.action) {
      case "ciphertext":
        return NextResponse.json({ state: await tamperCiphertext(actor, id) });
      case "signature":
        return NextResponse.json({ state: await tamperSignature(actor, id) });
      case "replay":
        return NextResponse.json({ state: await tamperReplay(actor, id) });
      case "algorithm":
        return NextResponse.json({ state: await tamperAlgorithmLabel(actor, id) });
      case "key-substitution":
        return NextResponse.json({ state: await tamperKeySubstitution(actor, id) });
      case "timestamp-swap":
        return NextResponse.json({ state: await tamperTimestampSwap(actor, id) });
      case "restore":
        return NextResponse.json({ state: await restoreTamper(actor, id) });
      default:
        throw new BadRequestError("Expected action to be one of: ciphertext, signature, replay, algorithm, key-substitution, timestamp-swap, restore");
    }
  } catch (error) {
    return errorResponse(error);
  }
}
