import { describe, it, expect, jest, beforeEach } from "@jest/globals";
import { inspect } from "node:util";
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
const { JWTVerifier } = await import("@keycardai/oauth/jwt/verifier");

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

  it("rows 1, 12, 12a and 12c: challenges only the configured path and query", async () => {
    const options = { issuers: "https://auth.keycard.ai", resourceIdentifier: "https://example.com/mcp?q=1" };
    for (const [path, challenge] of [
      ["/mcp?q=1", 'Bearer resource_metadata="https://example.com/.well-known/oauth-protected-resource/mcp?q=1"'],
      ["/mcp?q=2", "Bearer"],
      ["/tools", "Bearer"],
    ]) {
      const result = await verifyBearerToken(new Request("http://internal.example" + path, {
        headers: { "x-forwarded-host": "attacker.example", "x-forwarded-proto": "http" },
      }), options) as Response;
      expect(result.status).toBe(401);
      expect(result.headers.get("WWW-Authenticate")).toBe(challenge);
    }
  });

  it("row 15: verifies the exact configured audience behind a proxy", async () => {
    const resourceIdentifier = "https://example.com/mcp?q=1";
    const issuers = "https://auth.keycard.ai";
    mockVerify.mockResolvedValue({ client_id: "client", aud: resourceIdentifier });
    const result = await verifyBearerToken(new Request("http://internal.example/mcp?q=1", {
      headers: { authorization: "Bearer token" },
    }), { issuers, resourceIdentifier });
    expect(isAuthError(result)).toBe(false);
    expect(JWTVerifier).toHaveBeenCalledWith(expect.anything(), { issuers, audiences: resourceIdentifier });
  });

  it("rows 16, 16c and 17: verifier and challenge agree on the zone binding", async () => {
    const issuers = "https://keycard.cloud";
    const a = "https://example.com/a/mcp";
    const perZone = {
      issuers,
      resourceIdentifiersByZone: { a, b: "https://example.com/b/mcp" },
      zoneResolver: (request: Request) => new URL(request.url).pathname.split("/")[1],
    };
    const anonymous = await verifyBearerToken(new Request("http://internal.example/a/mcp"), perZone) as Response;
    expect(anonymous.headers.get("WWW-Authenticate")).toContain("/oauth-protected-resource/a/mcp");
    const unknown = await verifyBearerToken(new Request("http://internal.example/c/mcp"), perZone) as Response;
    expect(unknown.status).toBe(401);
    expect(unknown.headers.get("WWW-Authenticate")).toBe("Bearer");
    mockVerify.mockResolvedValue({ client_id: "client", aud: a });
    const tokenRequest = new Request("http://internal.example/a/mcp", { headers: { authorization: "Bearer token" } });
    expect(isAuthError(await verifyBearerToken(tokenRequest, perZone))).toBe(false);
    expect(JWTVerifier).toHaveBeenLastCalledWith(expect.anything(), { issuers: "https://a.keycard.cloud", audiences: a });
    expect(isAuthError(await verifyBearerToken(tokenRequest, {
      issuers,
      resourceIdentifiersByZone: { a, b: a },
      multiResource: true,
      audiences: [a],
    }))).toBe(false);
    expect(JWTVerifier).toHaveBeenLastCalledWith(expect.anything(), {
      issuers: ["https://a.keycard.cloud", "https://b.keycard.cloud"],
      audiences: a,
    });
  });

  it("rows 8e, 14b, 16d and 17a: rejects invalid modes before starting verification", async () => {
    const a = "https://example.com/mcp";
    const b = "https://example.com/other";
    for (const options of [
      { multiResource: true, audiences: [] },
      { multiResource: true, audiences: a },
      { resourceIdentifiersByZone: { a } },
      { multiResource: true, audiences: [a], resourceIdentifiersByZone: { a, b } },
    ]) {
      await expect(verifyBearerToken(makeRequest(), { issuers: "https://keycard.cloud", ...options }))
        .rejects.toMatchObject({ name: "ConfigurationError" });
    }
    expect(JWTVerifier).not.toHaveBeenCalled();
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

  it("prints the AuthInfo without the bearer token", async () => {
    const exp = Math.floor(Date.now() / 1000) + 3600;
    mockVerify.mockResolvedValue({ sub: "user-123", client_id: "app-456", scope: "read", exp, iss: "https://auth.keycard.ai" });

    const result = await verifyBearerToken(makeRequest("Bearer valid-token"), { issuers: "https://auth.keycard.ai" });

    if (isAuthError(result)) {
      throw new Error(`Expected AuthInfo, got Response with status ${result.status}`);
    }
    // util.inspect is what console.log uses. The printed form leaves out the
    // bearer token and keeps every other field.
    const { token: _token, ...shown } = result;
    const printed = inspect(result, { breakLength: Infinity });
    expect(printed).toBe(`AuthInfo ${inspect(shown, { breakLength: Infinity })}`);
    expect(printed).not.toContain("valid-token");
    expect(JSON.parse(JSON.stringify(result)).token).toBe("valid-token");
  });

  it.each([
    { row: "4a", aud: ["resource-a", "resource-b"], act: { sub: "actor", act: { sub: "previous" } }, expected: ["resource-a", "resource-b"] },
    { row: "4b", aud: "resource-a", act: undefined, expected: ["resource-a"] },
  ])("row $row: exposes the verified audiences and actor chain", async ({ aud, act, expected }) => {
    mockVerify.mockResolvedValue({ client_id: "client", aud, act });

    const caller = await verifyBearerToken(makeRequest("Bearer valid-token"), {
      issuers: "https://auth.keycard.ai",
      audiences: "resource-a",
    });

    if (isAuthError(caller)) throw new Error(`Expected AuthInfo, got status ${caller.status}`);
    expect(caller.aud).toEqual(expected);
    expect(caller.act).toEqual(act);
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

  describe("resource check", () => {
    const URN = "urn:openshell-claude-sandbox";

    function verifiedClaims(aud: string) {
      mockVerify.mockResolvedValue({
        sub: "user-123",
        client_id: "app-456",
        scope: "read",
        aud,
        exp: Math.floor(Date.now() / 1000) + 3600,
        iss: "https://auth.keycard.ai",
      });
    }

    it("rejects an http(s) resource on a different origin", async () => {
      verifiedClaims("https://other.example.com/mcp");
      const result = await verifyBearerToken(makeRequest("Bearer valid-token"), {
        issuers: "https://auth.keycard.ai",
        audiences: "https://other.example.com/mcp",
      });
      expect(isAuthError(result)).toBe(true);
      expect((result as Response).status).toBe(401);
      expect((result as Response).headers.get("WWW-Authenticate")).toContain("Token not intended for resource");
    });

    it("accepts a URN resource that matches a configured audience", async () => {
      verifiedClaims(URN);
      const result = await verifyBearerToken(makeRequest("Bearer valid-token"), {
        issuers: "https://auth.keycard.ai",
        audiences: [URN],
      });
      if (isAuthError(result)) {
        throw new Error(`Expected AuthInfo, got Response with status ${result.status}`);
      }
      expect(result.resource?.href).toBe(URN);
    });

    it("rejects a URN resource when no audiences are configured", async () => {
      verifiedClaims(URN);
      const result = await verifyBearerToken(makeRequest("Bearer valid-token"), {
        issuers: "https://auth.keycard.ai",
      });
      expect(isAuthError(result)).toBe(true);
      expect((result as Response).status).toBe(401);
    });

    it("rejects a URN resource that is not a configured audience", async () => {
      verifiedClaims("urn:some-other-service");
      const result = await verifyBearerToken(makeRequest("Bearer valid-token"), {
        issuers: "https://auth.keycard.ai",
        audiences: URN,
      });
      expect(isAuthError(result)).toBe(true);
      expect((result as Response).status).toBe(401);
    });
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
