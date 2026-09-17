import { describe, it, expect, jest, beforeEach, afterEach } from "@jest/globals";

// Each case re-imports ../auth.js after resetModules so the module-level
// "warned once" flag starts fresh.
jest.unstable_mockModule("@keycardai/oauth/keyring", () => ({
  JWKSOAuthKeyring: jest.fn().mockImplementation(() => ({ key: jest.fn() })),
}));

jest.unstable_mockModule("@keycardai/oauth/jwt/verifier", () => ({
  JWTVerifier: jest.fn().mockImplementation(() => ({
    verify: jest.fn<() => Promise<unknown>>().mockResolvedValue({
      client_id: "client-1",
      scope: "read",
      exp: Math.floor(Date.now() / 1000) + 3600,
    }),
  })),
}));

async function freshVerifyBearerToken() {
  jest.resetModules();
  const mod = await import("../auth.js");
  return mod.verifyBearerToken;
}

function makeRequest(): Request {
  const headers = new Headers();
  headers.set("Authorization", "Bearer token");
  return new Request("https://example.com/mcp", { headers });
}

describe("verifyBearerToken missing-audience warning", () => {
  let warn: ReturnType<typeof jest.spyOn>;
  beforeEach(() => {
    warn = jest.spyOn(console, "warn").mockImplementation(() => {});
  });
  afterEach(() => {
    warn.mockRestore();
  });

  it("warns once per isolate across two requests without audiences", async () => {
    const verifyBearerToken = await freshVerifyBearerToken();
    await verifyBearerToken(makeRequest(), { issuers: "https://auth.keycard.ai" });
    await verifyBearerToken(makeRequest(), { issuers: "https://auth.keycard.ai" });
    expect(warn).toHaveBeenCalledTimes(1);
    expect(String(warn.mock.calls[0][0])).toMatch(/set audiences/);
  });

  it("treats an empty audiences array as missing", async () => {
    const verifyBearerToken = await freshVerifyBearerToken();
    await verifyBearerToken(makeRequest(), { issuers: "https://auth.keycard.ai", audiences: [] });
    expect(warn).toHaveBeenCalledTimes(1);
  });

  it("does not warn when audiences is configured", async () => {
    const verifyBearerToken = await freshVerifyBearerToken();
    await verifyBearerToken(makeRequest(), {
      issuers: "https://auth.keycard.ai",
      audiences: "https://example.com",
    });
    await verifyBearerToken(makeRequest(), {
      issuers: "https://auth.keycard.ai",
      audiences: ["https://example.com"],
    });
    expect(warn).not.toHaveBeenCalled();
  });
});
