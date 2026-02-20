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

    ctx.setError({ error: "Global failure" });
    expect(() => ctx.access("https://api.example.com")).toThrow(ResourceAccessError);
  });

  it("should throw ResourceAccessError when resource has error", () => {
    const ctx = new AccessContext();
    ctx.setResourceError("https://api.example.com", { error: "Failed" });

    expect(() => ctx.access("https://api.example.com")).toThrow(ResourceAccessError);
  });

  it("should track error states correctly", () => {
    const ctx = new AccessContext();

    // Initially no errors
    expect(ctx.hasErrors()).toBe(false);
    expect(ctx.getStatus()).toBe("success");

    // Set resource error → partial_error
    ctx.setResourceError("https://api1.com", { error: "Failed" });
    expect(ctx.hasErrors()).toBe(true);
    expect(ctx.hasResourceError("https://api1.com")).toBe(true);
    expect(ctx.getStatus()).toBe("partial_error");

    // Set global error → error
    ctx.setError({ error: "Global failure" });
    expect(ctx.hasError()).toBe(true);
    expect(ctx.getStatus()).toBe("error");
  });

  it("should clear error when setting token for same resource", () => {
    const ctx = new AccessContext();

    ctx.setResourceError("https://api.test.com", { error: "Failed" });
    expect(ctx.hasResourceError("https://api.test.com")).toBe(true);

    ctx.setToken("https://api.test.com", { accessToken: "new_token", tokenType: "bearer" });
    expect(ctx.hasResourceError("https://api.test.com")).toBe(false);
    expect(ctx.access("https://api.test.com").accessToken).toBe("new_token");
  });

  it("should clear token when setting error for same resource", () => {
    const ctx = new AccessContext();

    ctx.setToken("https://api.test.com", { accessToken: "original_token", tokenType: "bearer" });
    ctx.setResourceError("https://api.test.com", { error: "Now failed" });

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
    ctx.setResourceError("https://fail.com", { error: "fail" });

    expect(ctx.getSuccessfulResources()).toEqual(["https://ok.com"]);
    expect(ctx.getFailedResources()).toEqual(["https://fail.com"]);
  });

  it("should return all errors via getErrors()", () => {
    const ctx = new AccessContext();
    ctx.setResourceError("https://api1.com", { error: "err1" });
    ctx.setError({ error: "global" });

    const errors = ctx.getErrors();
    expect(errors.error).toEqual({ error: "global" });
    expect(errors.resourceErrors["https://api1.com"]).toEqual({ error: "err1" });
  });

  it("should return null for getError() when no global error", () => {
    const ctx = new AccessContext();
    expect(ctx.getError()).toBeNull();
  });

  it("should return null for getResourceErrors() when no error for resource", () => {
    const ctx = new AccessContext();
    expect(ctx.getResourceErrors("https://nonexistent.com")).toBeNull();
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

  describe("grant() middleware", () => {
    it("should set error on accessContext when no auth info present", async () => {
      const provider = new AuthProvider({ zoneUrl: "https://test.keycard.cloud" });
      const middleware = provider.grant("https://api.example.com");

      const req: any = { headers: {} };
      const res: any = {};
      const next = jest.fn();

      await middleware(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(req.accessContext).toBeDefined();
      expect(req.accessContext.hasError()).toBe(true);
      expect(req.accessContext.getError()!.error).toContain("No authentication token");
    });

    it("should always call next() even on error", async () => {
      const provider = new AuthProvider({ zoneUrl: "https://test.keycard.cloud" });
      const middleware = provider.grant("https://api.example.com");

      const req: any = { headers: {} };
      const res: any = {};
      const next = jest.fn();

      await middleware(req, res, next);

      expect(next).toHaveBeenCalledTimes(1);
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
