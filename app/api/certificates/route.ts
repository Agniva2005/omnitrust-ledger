import { NextResponse } from "next/server";
import { z } from "zod";
import { errorResponse } from "@/lib/api";
import { AuthenticationError } from "@/lib/auth/rbac";
import { getSession } from "@/lib/auth/session";
import { ALGORITHMS, isAlgorithm } from "@/lib/crypto/orchestrator";
import { issueCertificate, listCertificates } from "@/lib/pki/certificates";

const schema = z.object({
  algorithm: z.string().refine(isAlgorithm),
  subjectUserId: z.string().optional(),
  validityDays: z.number().int().min(1).max(3650).optional(),
});

export async function GET() {
  try {
    const actor = await getSession();
    if (!actor) throw new AuthenticationError();
    return NextResponse.json({ certificates: await listCertificates(actor) });
  } catch (error) {
    return errorResponse(error);
  }
}

export async function POST(request: Request) {
  try {
    const actor = await getSession();
    if (!actor) throw new AuthenticationError();

    const parsed = schema.safeParse(await request.json().catch(() => null));
    if (!parsed.success) {
      return NextResponse.json(
        { error: `algorithm must be one of: ${ALGORITHMS.join(", ")}` },
        { status: 400 },
      );
    }

    // issueCertificate returns the stored key pair too, including the encrypted private key. It
    // must never leave the server, so the response carries only the key pair's id, state and
    // algorithm, the same view the list and detail routes give.
    const { keyPair, ...certificate } = await issueCertificate({ actor, ...parsed.data });
    return NextResponse.json(
      { certificate: { ...certificate, keyPair: { id: keyPair.id, status: keyPair.status, algorithm: keyPair.algorithm } } },
      { status: 201 },
    );
  } catch (error) {
    return errorResponse(error);
  }
}
