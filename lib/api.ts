import { NextResponse } from "next/server";
import { AuthenticationError, AuthorizationError } from "@/lib/auth/rbac";

export class BadRequestError extends Error {
  readonly status = 400;
  constructor(message: string) {
    super(message);
    this.name = "BadRequestError";
  }
}

export class NotFoundError extends Error {
  readonly status = 404;
  constructor(message = "Not found") {
    super(message);
    this.name = "NotFoundError";
  }
}

export class ConflictError extends Error {
  readonly status = 409;
  constructor(message: string) {
    super(message);
    this.name = "ConflictError";
  }
}

/**
 * Maps known error types onto status codes. Anything unrecognised becomes a 500
 * with a generic message, so internal details never reach the client.
 */
export function errorResponse(error: unknown): NextResponse {
  if (
    error instanceof AuthenticationError ||
    error instanceof AuthorizationError ||
    error instanceof BadRequestError ||
    error instanceof NotFoundError ||
    error instanceof ConflictError
  ) {
    return NextResponse.json({ error: error.message }, { status: error.status });
  }
  console.error("Unhandled API error:", error);
  return NextResponse.json({ error: "Internal server error" }, { status: 500 });
}
