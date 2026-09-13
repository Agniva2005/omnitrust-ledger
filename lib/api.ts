import { randomUUID } from "node:crypto";
import { NextResponse } from "next/server";
import { HttpError, TooManyRequestsError } from "@/lib/errors";

export {
  BadRequestError,
  ConflictError,
  HttpError,
  NotFoundError,
  TooManyRequestsError,
} from "@/lib/errors";

/**
 * What is safe to write to a server log about an unexpected error. Only the first line
 * of the message is kept: ORM errors echo the query arguments on the lines that follow,
 * and those arguments can include encrypted key material or personal data.
 */
export function redactErrorForLog(error: unknown): { name: string; code?: string; summary: string } {
  if (!(error instanceof Error)) return { name: typeof error, summary: "non-Error value thrown" };
  const code = (error as { code?: unknown }).code;
  return {
    name: error.name,
    code: typeof code === "string" ? code : undefined,
    summary: (error.message.split(/\r?\n/, 1)[0] ?? "").slice(0, 200),
  };
}

/**
 * Maps errors that carry a status onto that status. Anything else becomes a 500 with a
 * generic message and a correlation id, so internal details never reach the client.
 */
export function errorResponse(error: unknown): NextResponse {
  if (error instanceof HttpError) {
    const response = NextResponse.json({ error: error.message }, { status: error.status });
    if (error instanceof TooManyRequestsError) {
      response.headers.set("Retry-After", String(error.retryAfterSeconds));
    }
    return response;
  }

  const errorId = randomUUID();
  console.error("Unhandled API error", { errorId, ...redactErrorForLog(error) });
  return NextResponse.json({ error: "Internal server error", errorId }, { status: 500 });
}
