import { afterEach, describe, expect, it, vi } from "vitest";
import { errorResponse, redactErrorForLog, TooManyRequestsError } from "@/lib/api";
import { AuthorizationError } from "@/lib/auth/rbac";
import { InvalidTransitionError } from "@/lib/documents/lifecycle";
import { DocumentNotSignedError } from "@/lib/documents/verification";
import { InvalidKeyTransitionError } from "@/lib/pki/keys";

afterEach(() => {
  vi.restoreAllMocks();
});

describe("errorResponse status mapping", () => {
  it.each([
    [new AuthorizationError(), 403],
    [new InvalidTransitionError("HASHED", "VERIFIED"), 409],
    [new InvalidKeyTransitionError("REVOKED", "REVOKED", "certificate"), 409],
    [new DocumentNotSignedError(), 409],
    [new TooManyRequestsError("slow down", 30), 429],
  ])("maps %s to its own status rather than a 500", (error, status) => {
    expect(errorResponse(error).status).toBe(status);
  });

  it("tells a throttled client when to retry", () => {
    expect(errorResponse(new TooManyRequestsError("slow down", 42)).headers.get("Retry-After")).toBe(
      "42",
    );
  });
});

describe("unexpected errors", () => {
  it("return a generic 500 with a correlation id and no internal detail", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    const response = errorResponse(new Error("database file D:/secret/path is locked"));

    expect(response.status).toBe(500);
    const body = await response.json();
    expect(body.error).toBe("Internal server error");
    expect(body.errorId).toMatch(/^[0-9a-f-]{36}$/);
    expect(JSON.stringify(body)).not.toContain("secret");
  });

  it("log only the first line of the message, since ORM errors echo query arguments below it", () => {
    const logged = vi.spyOn(console, "error").mockImplementation(() => {});
    const ormError = new Error(
      "Invalid `prisma.keyPair.create()` invocation:\n\n{\n  data: { encryptedPrivateKey: 'SENSITIVE-CIPHERTEXT' }\n}",
    );

    errorResponse(ormError);

    const output = JSON.stringify(logged.mock.calls);
    expect(output).toContain("Invalid `prisma.keyPair.create()` invocation:");
    expect(output).not.toContain("SENSITIVE-CIPHERTEXT");
  });

  it("keep a machine-readable error code when one exists", () => {
    const error = Object.assign(new Error("Unique constraint failed"), { code: "P2002" });
    expect(redactErrorForLog(error)).toEqual({
      name: "Error",
      code: "P2002",
      summary: "Unique constraint failed",
    });
  });
});
