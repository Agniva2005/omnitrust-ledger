// Error types that carry an HTTP status. Kept free of imports so any layer (including
// edge middleware and client-safe modules) can use them without pulling in a runtime.

export abstract class HttpError extends Error {
  abstract readonly status: number;
}

export class BadRequestError extends HttpError {
  readonly status = 400;
  constructor(message: string) {
    super(message);
    this.name = "BadRequestError";
  }
}

export class NotFoundError extends HttpError {
  readonly status = 404;
  constructor(message = "Not found") {
    super(message);
    this.name = "NotFoundError";
  }
}

export class ConflictError extends HttpError {
  readonly status = 409;
  constructor(message: string) {
    super(message);
    this.name = "ConflictError";
  }
}

export class TooManyRequestsError extends HttpError {
  readonly status = 429;
  constructor(
    message: string,
    readonly retryAfterSeconds: number,
  ) {
    super(message);
    this.name = "TooManyRequestsError";
  }
}
