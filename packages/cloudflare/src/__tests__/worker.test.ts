import { describe, it, expect, jest, beforeEach } from "@jest/globals";
import type { AuthInfo, KeycardEnv } from "../types.js";

// Mock auth and metadata modules
jest.unstable_mockModule("../auth.js", () => ({
  verifyBearerToken: jest.fn(),
  isAuthError: jest.fn((result: unknown) => result instanceof Response),
}));

jest.unstable_mockModule("../metadata.js", () => ({
  handleMetadataRequest: jest.fn(),
}));

const { verifyBearerToken } = await import("../auth.js");
const { handleMetadataRequest } = await import("../metadata.js");
const { createKeycardWorker, resolveCredential } = await import("../worker.js");

const mockEnv: KeycardEnv = {
  KEYCARD_ISSUER: "https://z_abc123.keycard.cloud",
  KEYCARD_CLIENT_ID: "app-123",
  KEYCARD_CLIENT_SECRET: "secret-456",
};

const mockCtx: ExecutionContext = {
  waitUntil: jest.fn() as unknown as ExecutionContext["waitUntil"],
  passThroughOnException: jest.fn() as unknown as ExecutionContext["passThroughOnException"],
};

function makeAuthInfo(overrides?: Partial<AuthInfo>): AuthInfo {
  return {
    token: "test-token",
    clientId: "app-123",
    scopes: ["mcp:tools"],
    subject: "user-1",
    ...overrides,
  };
}

describe("createKeycardWorker", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("handles CORS preflight", async () => {
    const worker = createKeycardWorker({
      fetch: jest.fn<() => Promise<Response>>().mockResolvedValue(new Response("ok")),
    });

    const request = new Request("https://example.com/mcp", { method: "OPTIONS" });
    const response = await worker.fetch!(request, mockEnv, mockCtx);

    expect(response.status).toBe(204);
    expect(response.headers.get("Access-Control-Allow-Origin")).toBe("*");
  });

  it("delegates to metadata handler for well-known paths", async () => {
    const metadataResponse = new Response(JSON.stringify({ resource: "test" }));
    (handleMetadataRequest as jest.Mock).mockResolvedValue(metadataResponse);

    const fetchHandler = jest.fn<() => Promise<Response>>();
    const worker = createKeycardWorker({ fetch: fetchHandler });

    const request = new Request("https://example.com/.well-known/oauth-protected-resource");
    const response = await worker.fetch!(request, mockEnv, mockCtx);

    expect(response).toBe(metadataResponse);
    expect(fetchHandler).not.toHaveBeenCalled();
  });

  it("verifies bearer token and calls user handler on success", async () => {
    (handleMetadataRequest as jest.Mock).mockResolvedValue(null);
    const authInfo = makeAuthInfo();
    (verifyBearerToken as jest.Mock).mockResolvedValue(authInfo);

    const userResponse = new Response("success");
    const fetchHandler = jest.fn<() => Promise<Response>>().mockResolvedValue(userResponse);

    const worker = createKeycardWorker({
      requiredScopes: ["mcp:tools"],
      fetch: fetchHandler,
    });

    const request = new Request("https://example.com/mcp", {
      headers: { Authorization: "Bearer test-token" },
    });
    const response = await worker.fetch!(request, mockEnv, mockCtx);

    expect(response).toBe(userResponse);
    expect(fetchHandler).toHaveBeenCalledWith(request, mockEnv, mockCtx, authInfo);
  });

  it("returns auth error response without calling user handler", async () => {
    (handleMetadataRequest as jest.Mock).mockResolvedValue(null);
    const errorResponse = new Response(null, { status: 401 });
    (verifyBearerToken as jest.Mock).mockResolvedValue(errorResponse);

    const fetchHandler = jest.fn<() => Promise<Response>>();
    const worker = createKeycardWorker({ fetch: fetchHandler });

    const request = new Request("https://example.com/mcp");
    const response = await worker.fetch!(request, mockEnv, mockCtx);

    expect(response.status).toBe(401);
    expect(fetchHandler).not.toHaveBeenCalled();
  });
});

describe("resolveCredential", () => {
  it("returns WorkersClientSecret when client_id and secret are set", () => {
    const credential = resolveCredential({
      KEYCARD_ISSUER: "https://auth.keycard.ai",
      KEYCARD_CLIENT_ID: "app-123",
      KEYCARD_CLIENT_SECRET: "secret-456",
    });

    expect(credential.getAuth()).toEqual({
      clientId: "app-123",
      clientSecret: "secret-456",
    });
  });

  it("returns WorkersWebIdentity when private key is set", () => {
    const credential = resolveCredential({
      KEYCARD_ISSUER: "https://auth.keycard.ai",
      KEYCARD_PRIVATE_KEY: "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----",
    });

    expect(credential.getAuth()).toBeNull(); // WebIdentity returns null
  });

  it("prefers WebIdentity over ClientSecret when both are set", () => {
    const credential = resolveCredential({
      KEYCARD_ISSUER: "https://auth.keycard.ai",
      KEYCARD_PRIVATE_KEY: "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----",
      KEYCARD_CLIENT_ID: "app-123",
      KEYCARD_CLIENT_SECRET: "secret-456",
    });

    // WebIdentity takes precedence
    expect(credential.getAuth()).toBeNull();
  });

  it("throws when no credentials are configured", () => {
    expect(() =>
      resolveCredential({ KEYCARD_ISSUER: "https://auth.keycard.ai" }),
    ).toThrow("Missing Keycard credentials");
  });
});
