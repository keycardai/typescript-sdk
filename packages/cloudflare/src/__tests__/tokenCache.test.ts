import { describe, it, expect, jest, beforeEach } from "@jest/globals";
import type { TokenResponse, TokenExchangeRequest } from "@keycardai/oauth/tokenExchange";

// Mock TokenExchangeClient
jest.unstable_mockModule("@keycardai/oauth/tokenExchange", () => ({
  TokenExchangeClient: jest.fn().mockImplementation(() => ({
    exchangeToken: jest.fn(),
  })),
}));

const { TokenExchangeClient } = await import("@keycardai/oauth/tokenExchange");
const { IsolateSafeTokenCache } = await import("../tokenCache.js");

function mockTokenResponse(overrides?: Partial<TokenResponse>): TokenResponse {
  return {
    accessToken: "upstream-token-" + Math.random().toString(36).slice(2),
    tokenType: "bearer",
    expiresIn: 3600,
    ...overrides,
  };
}

describe("IsolateSafeTokenCache", () => {
  let client: InstanceType<typeof TokenExchangeClient>;
  let exchangeMock: jest.Mock;

  beforeEach(() => {
    jest.clearAllMocks();
    client = new TokenExchangeClient("https://auth.keycard.ai");
    exchangeMock = client.exchangeToken as jest.Mock;
  });

  it("exchanges token on cache miss", async () => {
    const response = mockTokenResponse();
    exchangeMock.mockResolvedValue(response);

    const cache = new IsolateSafeTokenCache(client);
    const result = await cache.getToken("user-1", "jwt-token", "https://api.github.com");

    expect(result).toBe(response);
    expect(exchangeMock).toHaveBeenCalledTimes(1);
  });

  it("returns cached token on cache hit", async () => {
    const response = mockTokenResponse();
    exchangeMock.mockResolvedValue(response);

    const cache = new IsolateSafeTokenCache(client);
    await cache.getToken("user-1", "jwt-token", "https://api.github.com");
    const result = await cache.getToken("user-1", "jwt-token", "https://api.github.com");

    expect(result).toBe(response);
    expect(exchangeMock).toHaveBeenCalledTimes(1); // only one exchange
  });

  it("isolates cache entries by user (subject)", async () => {
    const response1 = mockTokenResponse({ accessToken: "user-1-token" });
    const response2 = mockTokenResponse({ accessToken: "user-2-token" });
    exchangeMock.mockResolvedValueOnce(response1).mockResolvedValueOnce(response2);

    const cache = new IsolateSafeTokenCache(client);

    const result1 = await cache.getToken("user-1", "jwt-1", "https://api.github.com");
    const result2 = await cache.getToken("user-2", "jwt-2", "https://api.github.com");

    expect(result1.accessToken).toBe("user-1-token");
    expect(result2.accessToken).toBe("user-2-token");
    expect(exchangeMock).toHaveBeenCalledTimes(2);
  });

  it("isolates cache entries by resource", async () => {
    const response1 = mockTokenResponse({ accessToken: "github-token" });
    const response2 = mockTokenResponse({ accessToken: "gmail-token" });
    exchangeMock.mockResolvedValueOnce(response1).mockResolvedValueOnce(response2);

    const cache = new IsolateSafeTokenCache(client);

    const result1 = await cache.getToken("user-1", "jwt", "https://api.github.com");
    const result2 = await cache.getToken("user-1", "jwt", "https://gmail.googleapis.com");

    expect(result1.accessToken).toBe("github-token");
    expect(result2.accessToken).toBe("gmail-token");
  });

  it("deduplicates concurrent requests for the same user+resource", async () => {
    const response = mockTokenResponse();
    exchangeMock.mockImplementation(
      () => new Promise((resolve) => setTimeout(() => resolve(response), 50)),
    );

    const cache = new IsolateSafeTokenCache(client);

    const [r1, r2] = await Promise.all([
      cache.getToken("user-1", "jwt", "https://api.github.com"),
      cache.getToken("user-1", "jwt", "https://api.github.com"),
    ]);

    expect(r1).toBe(response);
    expect(r2).toBe(response);
    expect(exchangeMock).toHaveBeenCalledTimes(1);
  });

  it("evicts entries when maxEntries is exceeded", async () => {
    exchangeMock.mockImplementation(() => Promise.resolve(mockTokenResponse()));

    const cache = new IsolateSafeTokenCache(client, { maxEntries: 3 });

    // Fill cache beyond limit
    await cache.getToken("user-1", "jwt", "https://api1.com");
    await cache.getToken("user-2", "jwt", "https://api1.com");
    await cache.getToken("user-3", "jwt", "https://api1.com");
    await cache.getToken("user-4", "jwt", "https://api1.com"); // triggers eviction

    expect(exchangeMock).toHaveBeenCalledTimes(4);
  });

  it("respects skew seconds for early cache expiry", async () => {
    const response = mockTokenResponse({ expiresIn: 1 }); // 1 second TTL
    exchangeMock.mockResolvedValue(response);

    // With 30s skew (default), a 1s token is immediately expired in cache
    const cache = new IsolateSafeTokenCache(client);

    await cache.getToken("user-1", "jwt", "https://api.github.com");
    await cache.getToken("user-1", "jwt", "https://api.github.com");

    // Should have exchanged twice because the token is too short-lived
    expect(exchangeMock).toHaveBeenCalledTimes(2);
  });
});
