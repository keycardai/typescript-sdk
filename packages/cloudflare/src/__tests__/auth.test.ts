import { describe, it, expect, jest, beforeEach } from "@jest/globals";
import {
  JWKSKeyNotFoundError,
  JWKSFetchError,
  JWKSDiscoveryError,
} from "@keycardai/oauth/errors";

const mockVerify = jest.fn();

// Mock before any imports that trigger verifier creation
jest.unstable_mockModule("@keycardai/oauth/keyring", () => ({
  JWKSOAuthKeyring: jest.fn().mockImplementation(() => ({
    key: jest.fn(),
  })),
}));

jest.unstable_mockModule("@keycardai/oauth/jwt/verifier", () => ({
  JWTVerifier: jest.fn().mockImplementation(() => ({
    verify: mockVerify,
  })),
}));

const { verifyBearerToken, isAuthError } = await import("../auth.js");

function makeRequest(authHeader?: string): Request {
  const headers = new Headers();
  if (authHeader) {
    headers.set("Authorization", authHeader);
  }
  return new Request("https://example.com/mcp", { headers });
}

describe("verifyBearerToken", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("returns 401 when no Authorization header is present", async () => {
    const result = await verifyBearerToken(makeRequest(), { issuers: "https://auth.keycard.ai" });
    expect(isAuthError(result)).toBe(true);
    expect((result as Response).status).toBe(401);
  });

  it("returns 400 for malformed credentials (scheme only)", async () => {
    const result = await verifyBearerToken(makeRequest("Bearer"), { issuers: "https://auth.keycard.ai" });
    expect(isAuthError(result)).toBe(true);
    expect((result as Response).status).toBe(400);
  });

  it("returns 401 for non-Bearer scheme", async () => {
    const result = await verifyBearerToken(makeRequest("Basic abc123"), { issuers: "https://auth.keycard.ai" });
    expect(isAuthError(result)).toBe(true);
    expect((result as Response).status).toBe(401);
  });

  it("returns AuthInfo on successful verification", async () => {
    mockVerify.mockResolvedValue({
      sub: "user-123",
      client_id: "app-456",
      scope: "mcp:tools read",
      exp: Math.floor(Date.now() / 1000) + 3600,
      iss: "https://auth.keycard.ai",
    });

    const result = await verifyBearerToken(makeRequest("Bearer valid-token"), { issuers: "https://auth.keycard.ai" });

    if (isAuthError(result)) {
      throw new Error(`Expected AuthInfo, got Response with status ${result.status}`);
    }

    expect(result.subject).toBe("user-123");
    expect(result.clientId).toBe("app-456");
    expect(result.scopes).toEqual(["mcp:tools", "read"]);
    expect(result.token).toBe("valid-token");
  });

  it("exposes the caller identity claims from a Keycard token", async () => {
    mockVerify.mockResolvedValue({
      sub: "alice@example.com",
      sub_profile: "user",
      keycard_app_id: "app-456",
      client_id: "cred-123",
      scope: "read",
      exp: Math.floor(Date.now() / 1000) + 3600,
      iss: "https://auth.keycard.ai",
    });

    const result = await verifyBearerToken(makeRequest("Bearer valid-token"), { issuers: "https://auth.keycard.ai" });

    if (isAuthError(result)) {
      throw new Error(`Expected AuthInfo, got Response with status ${result.status}`);
    }

    expect(result.clientId).toBe("cred-123");
    expect(result.subject).toBe("alice@example.com");
    expect(result.subProfile).toBe("user");
    expect(result.keycardAppId).toBe("app-456");
  });

  it("leaves the Keycard identity claims undefined when the token lacks them", async () => {
    mockVerify.mockResolvedValue({
      sub: "some-subject",
      client_id: "app-456",
      scope: "read",
      exp: Math.floor(Date.now() / 1000) + 3600,
      iss: "https://auth.keycard.ai",
    });

    const result = await verifyBearerToken(makeRequest("Bearer valid-token"), { issuers: "https://auth.keycard.ai" });

    if (isAuthError(result)) {
      throw new Error(`Expected AuthInfo, got Response with status ${result.status}`);
    }

    expect(result.clientId).toBe("app-456");
    expect(result.subject).toBe("some-subject");
    expect(result.subProfile).toBeUndefined();
    expect(result.keycardAppId).toBeUndefined();
  });

  it("returns 403 when required scopes are missing", async () => {
    mockVerify.mockResolvedValue({
      sub: "user-123",
      client_id: "app-456",
      scope: "read",
      exp: Math.floor(Date.now() / 1000) + 3600,
      iss: "https://auth.keycard.ai",
    });

    const result = await verifyBearerToken(makeRequest("Bearer valid-token"), {
      issuers: "https://auth.keycard.ai",
      requiredScopes: ["mcp:tools"],
    });

    expect(isAuthError(result)).toBe(true);
    expect((result as Response).status).toBe(403);
  });

  it("returns 401 for expired tokens", async () => {
    mockVerify.mockResolvedValue({
      sub: "user-123",
      client_id: "app-456",
      scope: "mcp:tools",
      exp: Math.floor(Date.now() / 1000) - 100,
      iss: "https://auth.keycard.ai",
    });

    const result = await verifyBearerToken(makeRequest("Bearer expired-token"), { issuers: "https://auth.keycard.ai" });
    expect(isAuthError(result)).toBe(true);
    expect((result as Response).status).toBe(401);
  });

  it("throws a clear error when issuers is unset (e.g. KEYCARD_ISSUER env binding missing)", async () => {
    await expect(
      verifyBearerToken(makeRequest("Bearer tok"), { issuers: undefined as unknown as string }),
    ).rejects.toThrow(/KEYCARD_ISSUER env binding is required|`issuers` is required/);
  });

  it("includes WWW-Authenticate header with resource_metadata URL", async () => {
    const result = (await verifyBearerToken(makeRequest(), { issuers: "https://auth.keycard.ai" })) as Response;
    const wwwAuth = result.headers.get("WWW-Authenticate");
    expect(wwwAuth).toContain("resource_metadata=");
    expect(wwwAuth).toContain("/.well-known/oauth-protected-resource");
  });

  it("returns 401 invalid_token when the token's signing key is not in the JWKS", async () => {
    mockVerify.mockRejectedValue(
      new JWKSKeyNotFoundError('Failed to find key "kid-1" of "https://auth.keycard.ai"'),
    );

    const result = await verifyBearerToken(makeRequest("Bearer forged-token"), {
      issuers: "https://auth.keycard.ai",
    });

    expect(isAuthError(result)).toBe(true);
    const response = result as Response;
    expect(response.status).toBe(401);
    const wwwAuth = response.headers.get("WWW-Authenticate");
    expect(wwwAuth).toContain('error="invalid_token"');
    expect(wwwAuth).toContain("resource_metadata=");
  });

  it("returns 503 without WWW-Authenticate when the JWKS endpoint is unavailable", async () => {
    mockVerify.mockRejectedValue(new JWKSFetchError("JWKS endpoint returned 502"));

    const result = await verifyBearerToken(makeRequest("Bearer valid-token"), {
      issuers: "https://auth.keycard.ai",
    });

    expect(isAuthError(result)).toBe(true);
    const response = result as Response;
    expect(response.status).toBe(503);
    expect(response.headers.get("WWW-Authenticate")).toBeNull();
    expect(await response.json()).toEqual({ error: "temporarily_unavailable" });
  });

  it("returns 503 when issuer discovery fails", async () => {
    mockVerify.mockRejectedValue(new JWKSDiscoveryError("Failed to discover jwks_uri"));

    const result = await verifyBearerToken(makeRequest("Bearer valid-token"), {
      issuers: "https://auth.keycard.ai",
    });

    expect(isAuthError(result)).toBe(true);
    expect((result as Response).status).toBe(503);
  });

  it("rethrows genuinely unexpected errors instead of masking them as 401", async () => {
    mockVerify.mockRejectedValue(new TypeError("boom"));

    await expect(
      verifyBearerToken(makeRequest("Bearer valid-token"), {
        issuers: "https://auth.keycard.ai",
      }),
    ).rejects.toThrow("boom");
  });
});
