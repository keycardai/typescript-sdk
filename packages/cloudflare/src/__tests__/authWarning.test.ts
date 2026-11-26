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
    expect(String(warn.mock.calls[0][0])).toMatch(/resource_identifier/);
  });

  it("row 8e: rejects an empty audience list before authentication without warning", async () => {
    const verifyBearerToken = await freshVerifyBearerToken();
    await expect(verifyBearerToken(new Request("https://example.com/mcp"), {
      issuers: "https://auth.keycard.ai", audiences: [],
    })).rejects.toMatchObject({ name: "ConfigurationError", message: expect.stringContaining("audiences") });
    expect(warn).not.toHaveBeenCalled();
  });

  it("rows 14 and 14a: warns once across legacy scalar and list audience calls", async () => {
    const verifyBearerToken = await freshVerifyBearerToken();
    await verifyBearerToken(makeRequest(), {
      issuers: "https://auth.keycard.ai",
      audiences: "https://example.com",
    });
    await verifyBearerToken(makeRequest(), {
      issuers: "https://auth.keycard.ai",
      audiences: ["https://example.com"],
    });
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn).toHaveBeenCalledWith(expect.stringContaining("resource_identifier"));
  });

  it("metadata row 8f: warns once across the stateless verification and metadata APIs", async () => {
    const verifyBearerToken = await freshVerifyBearerToken();
    const { handleMetadataRequest } = await import("../metadata.js");
    const metadata = new Request("https://example.com/.well-known/oauth-protected-resource");
    expect((await handleMetadataRequest(metadata, { issuer: "https://auth.keycard.ai" }))?.status).toBe(200);
    await verifyBearerToken(makeRequest(), { issuers: "https://auth.keycard.ai" });
    expect((await handleMetadataRequest(metadata, { issuer: "https://auth.keycard.ai" }))?.status).toBe(200);
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn).toHaveBeenCalledWith(expect.stringContaining("resource_identifier"));
  });
});
