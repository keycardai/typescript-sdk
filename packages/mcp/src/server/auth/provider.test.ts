import { jest } from "@jest/globals";
import { AccessContext } from "./provider.js";
import { ResourceAccessError } from "./errors.js";

// =============================================================================
// AccessContext Unit Tests
// =============================================================================

describe("AccessContext", () => {
  it("should retrieve a token for a resource", () => {
    const ctx = new AccessContext({
      "https://api.example.com": { accessToken: "test_token", tokenType: "bearer" },
    });

    const token = ctx.access("https://api.example.com");
    expect(token.accessToken).toBe("test_token");
  });

  it("should throw ResourceAccessError for missing resource", () => {
    const ctx = new AccessContext({
      "https://api.example.com": { accessToken: "token", tokenType: "bearer" },
    });

    expect(() => ctx.access("https://other.api.com")).toThrow(ResourceAccessError);
  });

  it("should throw ResourceAccessError when global error is set", () => {
    const ctx = new AccessContext({
      "https://api.example.com": { accessToken: "token", tokenType: "bearer" },
    });

    ctx.setError({ message: "Global failure" });
    expect(() => ctx.access("https://api.example.com")).toThrow(ResourceAccessError);
  });

  it("should throw ResourceAccessError when resource has error", () => {
    const ctx = new AccessContext();
    ctx.setResourceError("https://api.example.com", { message: "Failed" });

    expect(() => ctx.access("https://api.example.com")).toThrow(ResourceAccessError);
  });

  it("should track error states correctly", () => {
    const ctx = new AccessContext();

    // Initially no errors
    expect(ctx.hasErrors()).toBe(false);
    expect(ctx.getStatus()).toBe("success");

    // Set resource error → partial_error
    ctx.setResourceError("https://api1.com", { message: "Failed" });
    expect(ctx.hasErrors()).toBe(true);
    expect(ctx.hasResourceError("https://api1.com")).toBe(true);
    expect(ctx.getStatus()).toBe("partial_error");

    // Set global error → error
    ctx.setError({ message: "Global failure" });
    expect(ctx.hasError()).toBe(true);
    expect(ctx.getStatus()).toBe("error");
  });

  it("should clear error when setting token for same resource", () => {
    const ctx = new AccessContext();

    ctx.setResourceError("https://api.test.com", { message: "Failed" });
    expect(ctx.hasResourceError("https://api.test.com")).toBe(true);

    ctx.setToken("https://api.test.com", { accessToken: "new_token", tokenType: "bearer" });
    expect(ctx.hasResourceError("https://api.test.com")).toBe(false);
    expect(ctx.access("https://api.test.com").accessToken).toBe("new_token");
  });

  it("should clear token when setting error for same resource", () => {
    const ctx = new AccessContext();

    ctx.setToken("https://api.test.com", { accessToken: "original_token", tokenType: "bearer" });
    ctx.setResourceError("https://api.test.com", { message: "Now failed" });

    expect(() => ctx.access("https://api.test.com")).toThrow(ResourceAccessError);
    expect(ctx.getFailedResources()).toContain("https://api.test.com");
    expect(ctx.getSuccessfulResources()).not.toContain("https://api.test.com");
  });

  it("should set and retrieve bulk tokens", () => {
    const ctx = new AccessContext();
    ctx.setBulkTokens({
      "https://api1.com": { accessToken: "token1", tokenType: "bearer" },
      "https://api2.com": { accessToken: "token2", tokenType: "bearer" },
    });

    expect(ctx.access("https://api1.com").accessToken).toBe("token1");
    expect(ctx.access("https://api2.com").accessToken).toBe("token2");
    expect(ctx.getSuccessfulResources()).toHaveLength(2);
  });

  it("should return correct successful and failed resources", () => {
    const ctx = new AccessContext();
    ctx.setToken("https://ok.com", { accessToken: "ok", tokenType: "bearer" });
    ctx.setResourceError("https://fail.com", { message: "fail" });

    expect(ctx.getSuccessfulResources()).toEqual(["https://ok.com"]);
    expect(ctx.getFailedResources()).toEqual(["https://fail.com"]);
  });

  it("should return all errors via getErrors()", () => {
    const ctx = new AccessContext();
    ctx.setResourceError("https://api1.com", { message: "err1" });
    ctx.setError({ message: "global" });

    const errors = ctx.getErrors();
    expect(errors.error).toEqual({ message: "global" });
    expect(errors.resources["https://api1.com"]).toEqual({ message: "err1" });
  });

  it("should return null for getError() when no global error", () => {
    const ctx = new AccessContext();
    expect(ctx.getError()).toBeNull();
  });

  it("should return null for getResourceError() when no error for resource", () => {
    const ctx = new AccessContext();
    expect(ctx.getResourceError("https://nonexistent.com")).toBeNull();
  });
});

// =============================================================================
// AuthProvider Tests
// =============================================================================

describe("AuthProvider", () => {
  // Use dynamic import to allow mocking
  let AuthProvider: typeof import("./provider.js").AuthProvider;

  beforeEach(async () => {
    const module = await import("./provider.js");
    AuthProvider = module.AuthProvider;
  });

  it("should throw AuthProviderConfigurationError if neither zoneUrl nor zoneId provided", async () => {
    const { AuthProviderConfigurationError } = await import("./errors.js");
    expect(() => new AuthProvider({})).toThrow(AuthProviderConfigurationError);
  });

  it("should construct with zoneUrl", () => {
    const provider = new AuthProvider({ zoneUrl: "https://test.keycard.cloud" });
    expect(provider).toBeDefined();
  });

  it("should construct with zoneId", () => {
    const provider = new AuthProvider({ zoneId: "test-zone" });
    expect(provider).toBeDefined();
  });

  it("should construct with zoneId and custom baseUrl", () => {
    const provider = new AuthProvider({
      zoneId: "test-zone",
      baseUrl: "https://custom.example.com",
    });
    expect(provider).toBeDefined();
  });

  function mockResponse() {
    const res: any = {
      headers: {} as Record<string, string>,
      statusCode: undefined as number | undefined,
      body: undefined as unknown,
    };
    res.set = jest.fn((name: string, value: string) => {
      res.headers[name] = value;
      return res;
    });
    res.status = jest.fn((code: number) => {
      res.statusCode = code;
      return res;
    });
    res.json = jest.fn((body: unknown) => {
      res.body = body;
      return res;
    });
    return res;
  }

  describe("grant() middleware", () => {
    it("should respond 401 with a Bearer challenge and not call next() when no auth info present", async () => {
      const provider = new AuthProvider({ zoneUrl: "https://test.keycard.cloud" });
      const middleware = provider.grant("https://api.example.com");

      const req: any = { headers: {}, protocol: "https", host: "rs.example.com" };
      const res = mockResponse();
      const next = jest.fn();

      await middleware(req, res, next);

      expect(next).not.toHaveBeenCalled();
      expect(req.accessContext).toBeUndefined();
      expect(res.statusCode).toBe(401);
      expect(res.headers["WWW-Authenticate"]).toMatch(/^Bearer resource_metadata="/);
      expect((res.body as { error: string }).error).toBe("invalid_request");
    });

    it("should record a global error and call next() when the userIdentifier resolver throws", async () => {
      const provider = new AuthProvider({ zoneUrl: "https://test.keycard.cloud" });
      const middleware = provider.grant("https://api.example.com", {
        userIdentifier: () => {
          throw new Error("resolver exploded");
        },
      });

      const req: any = { headers: {}, auth: { token: "subject-tok" } };
      const res = mockResponse();
      const next = jest.fn();

      await middleware(req, res, next);

      expect(next).toHaveBeenCalledTimes(1);
      expect(req.accessContext.hasError()).toBe(true);
      expect(req.accessContext.getError()!.message).toContain("userIdentifier");
    });

    describe("with a mocked token endpoint", () => {
      const ZONE = "https://test-zone.keycard.cloud";
      let originalFetch: typeof fetch;
      let fetchMock: jest.Mock;

      beforeEach(() => {
        originalFetch = globalThis.fetch;
        fetchMock = jest.fn(async (input: Parameters<typeof fetch>[0]) => {
          const url = typeof input === "string" ? input : input.toString();
          if (url.includes("/.well-known/")) {
            return new Response(
              JSON.stringify({ issuer: ZONE, token_endpoint: `${ZONE}/token` }),
              { status: 200, headers: { "content-type": "application/json" } },
            );
          }
          return new Response(
            JSON.stringify({ access_token: "resource-tok", token_type: "bearer" }),
            { status: 200, headers: { "content-type": "application/json" } },
          );
        });
        globalThis.fetch = fetchMock as unknown as typeof fetch;
      });

      afterEach(() => {
        globalThis.fetch = originalFetch;
      });

      it("should merge tokens from stacked grant middlewares into one accessContext", async () => {
        const provider = new AuthProvider({ zoneUrl: ZONE });
        const first = provider.grant("https://api-a.example.com");
        const second = provider.grant("https://api-b.example.com");

        const req: any = { headers: {}, auth: { token: "subject-tok" } };
        const res = mockResponse();
        const next = jest.fn();

        await first(req, res, next);
        await second(req, res, next);

        expect(next).toHaveBeenCalledTimes(2);
        expect(req.accessContext.access("https://api-a.example.com").accessToken).toBe("resource-tok");
        expect(req.accessContext.access("https://api-b.example.com").accessToken).toBe("resource-tok");
        expect(req.accessContext.getStatus()).toBe("success");
      });

      it("should use the substitute-user impersonation exchange when userIdentifier is set", async () => {
        const provider = new AuthProvider({ zoneUrl: ZONE });
        const middleware = provider.grant("https://api.example.com", {
          userIdentifier: () => "alice@example.com",
        });

        const req: any = { headers: {}, auth: { token: "subject-tok" } };
        const res = mockResponse();
        const next = jest.fn();

        await middleware(req, res, next);

        expect(next).toHaveBeenCalledTimes(1);
        expect(req.accessContext.getStatus()).toBe("success");

        const tokenCall = fetchMock.mock.calls.find(
          ([url]) => typeof url === "string" && (url as string).endsWith("/token"),
        );
        expect(tokenCall).toBeDefined();
        const body = ((tokenCall![1] as RequestInit).body ?? "") as string;
        const params = new URLSearchParams(body);
        expect(params.get("subject_token_type")).toBe(
          "urn:keycard:params:oauth:token-type:substitute-user",
        );
        const subjectToken = params.get("subject_token")!;
        const payload = JSON.parse(
          Buffer.from(subjectToken.split(".")[1], "base64url").toString("utf8"),
        );
        expect(payload.sub).toBe("alice@example.com");
      });

      it("should apply a string requestScopes to every resource", async () => {
        const provider = new AuthProvider({ zoneUrl: ZONE });
        const middleware = provider.grant(
          ["https://api-a.example.com", "https://api-b.example.com"],
          { requestScopes: "read write" },
        );

        const req: any = { headers: {}, auth: { token: "subject-tok" } };
        const res = mockResponse();
        const next = jest.fn();

        await middleware(req, res, next);

        const tokenCalls = fetchMock.mock.calls.filter(
          ([url]) => typeof url === "string" && (url as string).endsWith("/token"),
        );
        expect(tokenCalls).toHaveLength(2);
        for (const call of tokenCalls) {
          const params = new URLSearchParams(((call[1] as RequestInit).body ?? "") as string);
          expect(params.get("scope")).toBe("read write");
        }
      });

      it("should apply a record requestScopes per resource", async () => {
        const RES_A = "https://api-a.example.com";
        const RES_B = "https://api-b.example.com";
        const RES_C = "https://api-c.example.com";
        const provider = new AuthProvider({ zoneUrl: ZONE });
        const middleware = provider.grant([RES_A, RES_B, RES_C], {
          requestScopes: {
            [RES_A]: ["read", "write"],
            [RES_B]: "admin",
          },
        });

        const req: any = { headers: {}, auth: { token: "subject-tok" } };
        const res = mockResponse();
        const next = jest.fn();

        await middleware(req, res, next);

        const scopeFor = (resource: string) => {
          const tokenCalls = fetchMock.mock.calls.filter(
            ([url]) => typeof url === "string" && (url as string).endsWith("/token"),
          );
          for (const c of tokenCalls) {
            const params = new URLSearchParams(((c[1] as RequestInit).body ?? "") as string);
            if (params.get("resource") === resource) return params.get("scope");
          }
          return null;
        };

        expect(scopeFor(RES_A)).toBe("read write");
        expect(scopeFor(RES_B)).toBe("admin");
        expect(scopeFor(RES_C)).toBeNull();
      });

      it("should send no scope param when requestScopes is unset", async () => {
        const provider = new AuthProvider({ zoneUrl: ZONE });
        const middleware = provider.grant("https://api.example.com");

        const req: any = { headers: {}, auth: { token: "subject-tok" } };
        const res = mockResponse();
        const next = jest.fn();

        await middleware(req, res, next);

        const tokenCall = fetchMock.mock.calls.find(
          ([url]) => typeof url === "string" && (url as string).endsWith("/token"),
        );
        const params = new URLSearchParams(((tokenCall![1] as RequestInit).body ?? "") as string);
        expect(params.get("scope")).toBeNull();
      });
    });
  });

  describe("exchangeTokens()", () => {
    it("should return AccessContext with error when client init fails", async () => {
      // Provider with unreachable zone URL — client init will fail on first exchange
      const provider = new AuthProvider({
        zoneUrl: "https://nonexistent.keycard.invalid",
      });

      const ctx = await provider.exchangeTokens("subject-token", "https://api.example.com");

      // Should have an error (either global or resource-level) since the zone URL is unreachable
      expect(ctx.hasErrors()).toBe(true);
    });
  });
});
