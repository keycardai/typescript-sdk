import { jest } from '@jest/globals';
import express, { Request, Response } from "express";
import * as net from "node:net";
import { inspect } from "node:util";
import type { AuthInfo, OAuthTokenVerifier } from "@modelcontextprotocol/server";
import { requireBearerAuth, type AuthenticatedRequest } from "./bearerAuth.js";
import { InvalidTokenError, InsufficientScopeError, JWKSKeyNotFoundError, JWKSFetchError, JWKSDiscoveryError } from "../errors.js";

// Mock verifier
const mockVerifyAccessToken = jest.fn();
const mockVerifier: OAuthTokenVerifier = {
  verifyAccessToken: mockVerifyAccessToken,
};

describe("requireBearerAuth middleware", () => {
  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;
  let nextFunction: jest.Mock;

  beforeEach(() => {
    mockRequest = {
      headers: {},
    };
    mockRequest.protocol = 'https';
    mockRequest.host = 'api.example.com';
    mockRequest.originalUrl = '/';
    mockResponse = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
      end: jest.fn(),
      set: jest.fn().mockReturnThis(),
    };
    nextFunction = jest.fn();
    jest.spyOn(console, 'error').mockImplementation(() => {});
  })

  afterEach(() => {
    jest.clearAllMocks();
  });

  it("should call next when token is valid", async () => {
    const validAuthInfo: AuthInfo = {
      token: "valid-token",
      clientId: "client-123",
      scopes: ["read", "write"],
    };
    mockVerifyAccessToken.mockResolvedValue(validAuthInfo);

    mockRequest.headers = {
      authorization: "Bearer valid-token",
    };

    const middleware = requireBearerAuth({ verifier: mockVerifier });
    await middleware(mockRequest as Request, mockResponse as Response, nextFunction);

    expect(mockVerifyAccessToken).toHaveBeenCalledWith("valid-token");
    expect(mockRequest.auth).toEqual(validAuthInfo);
    expect(nextFunction).toHaveBeenCalled();
    expect(mockResponse.status).not.toHaveBeenCalled();
    expect(mockResponse.json).not.toHaveBeenCalled();
    expect(mockResponse.end).not.toHaveBeenCalled();
  });

  it("should reject expired tokens", async () => {
    const expiredAuthInfo: AuthInfo = {
      token: "expired-token",
      clientId: "client-123",
      scopes: ["read", "write"],
      expiresAt: Math.floor(Date.now() / 1000) - 100, // Token expired 100 seconds ago
    };
    mockVerifyAccessToken.mockResolvedValue(expiredAuthInfo);

    mockRequest.headers = {
      authorization: "Bearer expired-token",
    };

    const middleware = requireBearerAuth({ verifier: mockVerifier });
    await middleware(mockRequest as Request, mockResponse as Response, nextFunction);

    expect(mockVerifyAccessToken).toHaveBeenCalledWith("expired-token");
    expect(mockResponse.status).toHaveBeenCalledWith(401);
    expect(mockResponse.set).toHaveBeenCalledWith(
      "WWW-Authenticate",
      'Bearer error="invalid_token", error_description="Token has expired", resource_metadata="https://api.example.com/.well-known/oauth-protected-resource"'
    );
    expect(mockResponse.end).toHaveBeenCalled();
    expect(mockResponse.json).not.toHaveBeenCalled();
    expect(nextFunction).not.toHaveBeenCalled();
  });

  it("should accept non-expired tokens", async () => {
    const nonExpiredAuthInfo: AuthInfo = {
      token: "valid-token",
      clientId: "client-123",
      scopes: ["read", "write"],
      expiresAt: Math.floor(Date.now() / 1000) + 3600, // Token expires in an hour
    };
    mockVerifyAccessToken.mockResolvedValue(nonExpiredAuthInfo);

    mockRequest.headers = {
      authorization: "Bearer valid-token",
    };

    const middleware = requireBearerAuth({ verifier: mockVerifier });
    await middleware(mockRequest as Request, mockResponse as Response, nextFunction);

    expect(mockVerifyAccessToken).toHaveBeenCalledWith("valid-token");
    expect(mockRequest.auth).toEqual(nonExpiredAuthInfo);
    expect(nextFunction).toHaveBeenCalled();
    expect(mockResponse.status).not.toHaveBeenCalled();
    expect(mockResponse.json).not.toHaveBeenCalled();
    expect(mockResponse.end).not.toHaveBeenCalled();
  });

  it("should require specific scopes when configured", async () => {
    const authInfo: AuthInfo = {
      token: "valid-token",
      clientId: "client-123",
      scopes: ["read"],
    };
    mockVerifyAccessToken.mockResolvedValue(authInfo);

    mockRequest.headers = {
      authorization: "Bearer valid-token",
    };

    const middleware = requireBearerAuth({
      verifier: mockVerifier,
      requiredScopes: ["read", "write"]
    });

    await middleware(mockRequest as Request, mockResponse as Response, nextFunction);

    expect(mockVerifyAccessToken).toHaveBeenCalledWith("valid-token");
    expect(mockResponse.status).toHaveBeenCalledWith(403);
    expect(mockResponse.set).toHaveBeenCalledWith(
      "WWW-Authenticate",
      'Bearer error="insufficient_scope", error_description="Insufficient scope", resource_metadata="https://api.example.com/.well-known/oauth-protected-resource"'
    );
    expect(mockResponse.end).toHaveBeenCalled();
    expect(mockResponse.json).not.toHaveBeenCalled();
    expect(nextFunction).not.toHaveBeenCalled();
  });

  it("should accept token with all required scopes", async () => {
    const authInfo: AuthInfo = {
      token: "valid-token",
      clientId: "client-123",
      scopes: ["read", "write", "admin"],
    };
    mockVerifyAccessToken.mockResolvedValue(authInfo);

    mockRequest.headers = {
      authorization: "Bearer valid-token",
    };

    const middleware = requireBearerAuth({
      verifier: mockVerifier,
      requiredScopes: ["read", "write"]
    });

    await middleware(mockRequest as Request, mockResponse as Response, nextFunction);

    expect(mockVerifyAccessToken).toHaveBeenCalledWith("valid-token");
    expect(mockRequest.auth).toEqual(authInfo);
    expect(nextFunction).toHaveBeenCalled();
    expect(mockResponse.status).not.toHaveBeenCalled();
    expect(mockResponse.json).not.toHaveBeenCalled();
    expect(mockResponse.end).not.toHaveBeenCalled();
  });

  it("should return 401 when no Authorization header is present", async () => {
    const middleware = requireBearerAuth({ verifier: mockVerifier });
    await middleware(mockRequest as Request, mockResponse as Response, nextFunction);

    expect(mockVerifyAccessToken).not.toHaveBeenCalled();
    expect(mockResponse.status).toHaveBeenCalledWith(401);
    expect(mockResponse.set).toHaveBeenCalledWith(
      "WWW-Authenticate",
      'Bearer resource_metadata=\"https://api.example.com/.well-known/oauth-protected-resource\"'
    );
    expect(mockResponse.end).toHaveBeenCalled();
    expect(mockResponse.json).not.toHaveBeenCalled();
    expect(nextFunction).not.toHaveBeenCalled();
  });

  it("should return 400 when Authorization header format is malformed", async () => {
    mockRequest.headers = {
      authorization: "InvalidFormat",
    };

    const middleware = requireBearerAuth({ verifier: mockVerifier });
    await middleware(mockRequest as Request, mockResponse as Response, nextFunction);

    expect(mockVerifyAccessToken).not.toHaveBeenCalled();
    expect(mockResponse.status).toHaveBeenCalledWith(400);
    expect(mockResponse.set).not.toHaveBeenCalled();
    expect(mockResponse.end).toHaveBeenCalled();
    expect(mockResponse.json).not.toHaveBeenCalled();
    expect(nextFunction).not.toHaveBeenCalled();
  });

  it("should return 401 when Authorization header format is invalid", async () => {
    mockRequest.headers = {
      authorization: "InvalidFormat mF_9.B5f-4.1JqM",
    };

    const middleware = requireBearerAuth({ verifier: mockVerifier });
    await middleware(mockRequest as Request, mockResponse as Response, nextFunction);

    expect(mockVerifyAccessToken).not.toHaveBeenCalled();
    expect(mockResponse.status).toHaveBeenCalledWith(401);
    expect(mockResponse.set).toHaveBeenCalledWith(
      "WWW-Authenticate",
      'Bearer error="invalid_token", error_description="Unsupported authentication scheme", resource_metadata="https://api.example.com/.well-known/oauth-protected-resource"'
    );
    expect(mockResponse.end).toHaveBeenCalled();
    expect(mockResponse.json).not.toHaveBeenCalled();
    expect(nextFunction).not.toHaveBeenCalled();
  });

  it("should return 401 when token verification fails with InvalidTokenError", async () => {
    mockRequest.headers = {
      authorization: "Bearer invalid-token",
    };

    mockVerifyAccessToken.mockRejectedValue(new InvalidTokenError("Token expired"));

    const middleware = requireBearerAuth({ verifier: mockVerifier });
    await middleware(mockRequest as Request, mockResponse as Response, nextFunction);

    expect(mockVerifyAccessToken).toHaveBeenCalledWith("invalid-token");
    expect(mockResponse.status).toHaveBeenCalledWith(401);
    expect(mockResponse.set).toHaveBeenCalledWith(
      "WWW-Authenticate",
      'Bearer error="invalid_token", error_description="Token expired", resource_metadata="https://api.example.com/.well-known/oauth-protected-resource"'
    );
    expect(mockResponse.end).toHaveBeenCalled();
    expect(mockResponse.json).not.toHaveBeenCalled();
    expect(nextFunction).not.toHaveBeenCalled();
  });

  it("should return 403 when access token has insufficient scopes", async () => {
    mockRequest.headers = {
      authorization: "Bearer valid-token",
    };

    mockVerifyAccessToken.mockRejectedValue(new InsufficientScopeError("Required scopes: read, write"));

    const middleware = requireBearerAuth({ verifier: mockVerifier });
    await middleware(mockRequest as Request, mockResponse as Response, nextFunction);

    expect(mockVerifyAccessToken).toHaveBeenCalledWith("valid-token");
    expect(mockResponse.status).toHaveBeenCalledWith(403);
    expect(mockResponse.set).toHaveBeenCalledWith(
      "WWW-Authenticate",
      'Bearer error="insufficient_scope", error_description="Required scopes: read, write", resource_metadata="https://api.example.com/.well-known/oauth-protected-resource"'
    );
    expect(mockResponse.end).toHaveBeenCalled();
    expect(mockResponse.json).not.toHaveBeenCalled();
    expect(nextFunction).not.toHaveBeenCalled();
  });

  it("should return 401 invalid_token when the signing key is not in the JWKS", async () => {
    mockRequest.headers = {
      authorization: "Bearer forged-or-rotated-token",
    };

    mockVerifyAccessToken.mockRejectedValue(
      new JWKSKeyNotFoundError('Failed to find key "abc" of "https://zone.example.com"')
    );

    const middleware = requireBearerAuth({ verifier: mockVerifier });
    await middleware(mockRequest as Request, mockResponse as Response, nextFunction);

    expect(mockResponse.status).toHaveBeenCalledWith(401);
    expect(mockResponse.set).toHaveBeenCalledWith(
      "WWW-Authenticate",
      'Bearer error="invalid_token", error_description="Unable to verify token signing key", resource_metadata="https://api.example.com/.well-known/oauth-protected-resource"'
    );
    expect(mockResponse.end).toHaveBeenCalled();
    expect(mockResponse.json).not.toHaveBeenCalled();
    expect(nextFunction).not.toHaveBeenCalled();
  });

  it.each([
    ["JWKSFetchError", new JWKSFetchError("JWKS endpoint returned 503")],
    ["JWKSDiscoveryError", new JWKSDiscoveryError("Failed to discover authorization server metadata")],
  ])("should return 503 (not 500) when %s occurs", async (_name, error) => {
    mockRequest.headers = {
      authorization: "Bearer valid-looking-token",
    };

    mockVerifyAccessToken.mockRejectedValue(error);

    const middleware = requireBearerAuth({ verifier: mockVerifier });
    await middleware(mockRequest as Request, mockResponse as Response, nextFunction);

    expect(mockResponse.status).toHaveBeenCalledWith(503);
    expect(mockResponse.json).toHaveBeenCalledWith({ error: "temporarily_unavailable" });
    expect(mockResponse.set).not.toHaveBeenCalled();
    expect(nextFunction).not.toHaveBeenCalled();
  });

  it("should next with error when unexpected error occurs", async () => {
    mockRequest.headers = {
      authorization: "Bearer valid-token",
    };

    mockVerifyAccessToken.mockRejectedValue(new Error("Unexpected error"));

    const middleware = requireBearerAuth({ verifier: mockVerifier });
    await middleware(mockRequest as Request, mockResponse as Response, nextFunction);

    expect(mockVerifyAccessToken).toHaveBeenCalledWith("valid-token");
    expect(nextFunction).toHaveBeenCalledWith(new Error("Unexpected error"));
    expect(mockResponse.status).not.toHaveBeenCalled();
    expect(mockResponse.json).not.toHaveBeenCalled();
    expect(mockResponse.end).not.toHaveBeenCalled();
  });

  describe("resource check", () => {
    const URN = "urn:openshell-claude-sandbox";

    async function run(resource: URL, options: { audiences?: string | string[] } = {}) {
      mockVerifyAccessToken.mockResolvedValue({
        token: "valid-token",
        clientId: "client-123",
        scopes: [],
        resource,
      } as AuthInfo);
      mockRequest.headers = { authorization: "Bearer valid-token" };
      const middleware = requireBearerAuth({ verifier: mockVerifier, ...options });
      await middleware(mockRequest as Request, mockResponse as Response, nextFunction);
    }

    it("rejects an http(s) resource on a different origin", async () => {
      await run(new URL("https://other.example.com/mcp"));
      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.set).toHaveBeenCalledWith(
        "WWW-Authenticate",
        expect.stringContaining('error_description="Token not intended for resource"'),
      );
      expect(nextFunction).not.toHaveBeenCalled();
    });

    it("accepts a URN resource that matches a configured audience", async () => {
      await run(new URL(URN), { audiences: ["https://api.example.com", URN] });
      expect(nextFunction).toHaveBeenCalledWith();
      expect(mockResponse.status).not.toHaveBeenCalled();
    });

    it("accepts a URN resource that matches a single configured audience string", async () => {
      await run(new URL(URN), { audiences: URN });
      expect(nextFunction).toHaveBeenCalledWith();
      expect(mockResponse.status).not.toHaveBeenCalled();
    });

    it("rejects a URN resource when no audiences are configured", async () => {
      await run(new URL(URN));
      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(nextFunction).not.toHaveBeenCalled();
    });

    it("rejects a URN resource that is not a configured audience", async () => {
      await run(new URL("urn:some-other-service"), { audiences: URN });
      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(nextFunction).not.toHaveBeenCalled();
    });
  });

  describe("missing-audience warning at construction", () => {
    it("row 8e: rejects empty audiences even with a supplied verifier", () => {
      expect(() => requireBearerAuth({ verifier: mockVerifier, audiences: [] }))
        .toThrow(/audiences must not be an empty list/);
    });
    let warn: ReturnType<typeof jest.spyOn>;
    beforeEach(() => {
      warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
    });
    afterEach(() => {
      warn.mockRestore();
    });

    it("warns once when built from issuers without audiences", () => {
      requireBearerAuth({ issuers: "https://auth.example.com" });
      expect(warn).toHaveBeenCalledTimes(1);
      expect(String(warn.mock.calls[0][0])).toMatch(/resource_identifier/);
    });

    it("row 14a: warns once when built from issuers with a legacy scalar audience", () => {
      requireBearerAuth({
        issuers: "https://auth.example.com",
        audiences: "https://api.example.com",
      });
      expect(warn).toHaveBeenCalledTimes(1);
    });

    it("row 7: warns once for a legacy setup even with a custom verifier", () => {
      requireBearerAuth({ verifier: mockVerifier });
      expect(warn).toHaveBeenCalledTimes(1);
    });
  });

  describe("configured resource binding", () => {
    const resourceIdentifier = "https://api.example.com/mcp?q=1";
    const metadataUrl = "https://api.example.com/.well-known/oauth-protected-resource/mcp?q=1";

    it.each([
      { rows: "1, 12, 12c and gate 2", target: "/mcp?q=1", challenge: `Bearer resource_metadata="${metadataUrl}"` },
      { rows: "12a", target: "/mcp?q=2", challenge: "Bearer" },
    ])("rows $rows: matches request target, not host headers", async ({ target, challenge }) => {
      mockRequest.protocol = "http";
      mockRequest.host = "internal.example";
      mockRequest.headers = { "x-forwarded-host": "attacker.example", "x-forwarded-proto": "http" };
      mockRequest.originalUrl = target;
      await requireBearerAuth({ verifier: mockVerifier, resourceIdentifier })(mockRequest as Request, mockResponse as Response, nextFunction);
      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.set).toHaveBeenCalledWith("WWW-Authenticate", challenge);
    });

    it.each([
      { rows: "8, integration 2", aud: ["https://api.example.com/other"], status: 401, description: "invalid_token" },
      { rows: "15", aud: ["other", resourceIdentifier], status: undefined, description: undefined },
    ])("rows $rows: checks the exact configured audience", async ({ aud, status, description }) => {
      mockVerifyAccessToken.mockResolvedValue({ token: "token", clientId: "client", scopes: [], aud });
      mockRequest.headers = { authorization: "Bearer token" };
      mockRequest.originalUrl = "/mcp?q=1";
      await requireBearerAuth({ verifier: mockVerifier, resourceIdentifier })(mockRequest as Request, mockResponse as Response, nextFunction);
      if (status) {
        expect(mockResponse.status).toHaveBeenCalledWith(status);
        expect(mockResponse.set).toHaveBeenCalledWith("WWW-Authenticate", expect.stringContaining(description!));
      } else {
        expect(nextFunction).toHaveBeenCalledTimes(1);
      }
    });

    it.each([
      { aud: undefined, resource: resourceIdentifier, allowed: true },
      { aud: undefined, resource: "https://api.example.com/other", allowed: false },
      { aud: ["https://api.example.com/other"], resource: resourceIdentifier, allowed: false },
      { aud: [], resource: resourceIdentifier, allowed: false },
    ])("uses the custom verifier resource only when aud is absent: %j", async ({ aud, resource, allowed }) => {
      mockVerifyAccessToken.mockResolvedValue({ token: "token", clientId: "client", scopes: [], aud, resource: new URL(resource) });
      mockRequest.headers = { authorization: "Bearer token" };
      mockRequest.originalUrl = "/mcp?q=1";
      await requireBearerAuth({ verifier: mockVerifier, resourceIdentifier })(mockRequest as Request, mockResponse as Response, nextFunction);
      if (allowed) {
        expect(nextFunction).toHaveBeenCalledTimes(1);
      } else {
        expect(nextFunction).not.toHaveBeenCalled();
        expect(mockResponse.status).toHaveBeenCalledWith(401);
      }
    });

    it.each([
      "https://api.example.com",
      "https://API.EXAMPLE.COM/mcp",
      "https://api.example.com:443/mcp",
    ])("normalizes the URL fallback but compares aud exactly for %s", async configured => {
      const resource = new URL(configured);
      const verified = { token: "token", clientId: "client", scopes: [], resource };
      mockRequest.headers = { authorization: "Bearer token" };
      mockRequest.originalUrl = resource.pathname;
      for (const mode of [{ resourceIdentifier: configured }, { multiResource: true, audiences: ["opaque", configured] }]) {
        const handler = requireBearerAuth({ verifier: mockVerifier, ...mode });
        nextFunction.mockClear();
        mockVerifyAccessToken.mockResolvedValueOnce(verified);
        await handler(mockRequest as Request, mockResponse as Response, nextFunction);
        expect(nextFunction).toHaveBeenCalledTimes(1);
        mockVerifyAccessToken.mockResolvedValueOnce({ ...verified, aud: [resource.href] });
        await handler(mockRequest as Request, mockResponse as Response, nextFunction);
        expect(nextFunction).toHaveBeenCalledTimes(1);
        expect(mockResponse.status).toHaveBeenLastCalledWith(401);
        mockVerifyAccessToken.mockResolvedValueOnce({ ...verified, aud: [configured] });
        await handler(mockRequest as Request, mockResponse as Response, nextFunction);
        expect(nextFunction).toHaveBeenCalledTimes(2);
      }
    });

    it("reports the bound resource when it is not the first audience", async () => {
      const other = new URL("https://api.example.com/other");
      class VerifierAuth {
        #token = "test-token";
        get token() { return this.#token; }
        clientId = "client";
        scopes: string[] = [];
        aud = [other.href, resourceIdentifier];
        resource = other;
      }
      const authInfo = Object.freeze(new VerifierAuth());
      mockVerifyAccessToken.mockResolvedValue(authInfo);
      mockRequest.headers = { authorization: "Bearer test-token" };
      mockRequest.originalUrl = "/mcp?q=1";
      await requireBearerAuth({ verifier: mockVerifier, resourceIdentifier })(mockRequest as Request, mockResponse as Response, nextFunction);
      const auth = (mockRequest as AuthenticatedRequest).auth;
      expect(nextFunction).toHaveBeenCalledTimes(1);
      expect(auth.resource?.href).toBe(resourceIdentifier);
      expect(auth.aud).toEqual(authInfo.aud);
      expect(auth.token).toBe(authInfo.token);
      expect(inspect(auth)).not.toContain(authInfo.token);
    });

    it("gate row 6: does not advertise another route's document on insufficient scope", async () => {
      mockVerifyAccessToken.mockResolvedValue({ token: "token", clientId: "client", scopes: [], aud: [resourceIdentifier] });
      mockRequest.headers = { authorization: "Bearer token" };
      mockRequest.originalUrl = "/tools";
      await requireBearerAuth({ verifier: mockVerifier, resourceIdentifier, requiredScopes: ["write"] })(
        mockRequest as Request, mockResponse as Response, nextFunction,
      );
      expect(mockResponse.status).toHaveBeenCalledWith(403);
      expect(mockResponse.set).toHaveBeenCalledWith("WWW-Authenticate", expect.stringContaining("insufficient_scope"));
      expect(mockResponse.set).not.toHaveBeenCalledWith("WWW-Authenticate", expect.stringContaining("resource_metadata"));
    });

    it.each([{ resourceIdentifier: "urn:example:service" }, { allowAnyAudience: true }])(
      "gate row 7: verifier-only mode %j has no metadata challenge",
      async mode => {
        await requireBearerAuth({ verifier: mockVerifier, ...mode })(mockRequest as Request, mockResponse as Response, nextFunction);
        expect(mockResponse.status).toHaveBeenCalledWith(401);
        expect(mockResponse.set).toHaveBeenCalledWith("WWW-Authenticate", "Bearer");
      },
    );
  });


  describe("malformed Host header", () => {
    async function rawRequest(host: string, authorization?: string): Promise<{ status: number; unhandled: unknown[] }> {
      const unhandled: unknown[] = [];
      const app = express();
      app.use(requireBearerAuth({ verifier: mockVerifier }));
      app.get("/", (_req, res) => { res.status(200).end(); });
      app.use((err: unknown, _req: Request, res: Response, _next: () => void) => {
        unhandled.push(err);
        res.status(500).end();
      });
      const server = app.listen(0);
      await new Promise<void>((resolve) => server.once("listening", resolve));
      const { port } = server.address() as net.AddressInfo;
      try {
        const response = await new Promise<string>((resolve, reject) => {
          const socket = net.connect(port, "127.0.0.1");
          let data = "";
          socket.on("data", (chunk) => { data += chunk.toString(); });
          socket.on("end", () => resolve(data));
          socket.on("error", reject);
          const auth = authorization ? `Authorization: ${authorization}\r\n` : "";
          socket.write(`GET / HTTP/1.1\r\nHost: ${host}\r\n${auth}Connection: close\r\n\r\n`);
        });
        const status = Number(response.split(" ")[1]);
        return { status, unhandled };
      } finally {
        await new Promise<void>((resolve) => server.close(() => resolve()));
      }
    }

    it.each(["a b.example.com", "%zz.example.com", "[::1"])(
      "answers 400 for Host %p without an unhandled error",
      async (host) => {
        const result = await rawRequest(host);
        expect(result.status).toBe(400);
        expect(result.unhandled).toEqual([]);
        expect(mockVerifyAccessToken).not.toHaveBeenCalled();
      },
    );

    it("still answers 401 with a challenge for a well-formed Host and no credentials", async () => {
      const result = await rawRequest("api.example.com");
      expect(result.status).toBe(401);
      expect(result.unhandled).toEqual([]);
    });

    it("still passes a valid token through for a well-formed Host", async () => {
      mockVerifyAccessToken.mockResolvedValue({ token: "t", clientId: "c", scopes: [] });
      const result = await rawRequest("api.example.com", "Bearer t");
      expect(result.status).toBe(200);
      expect(result.unhandled).toEqual([]);
    });
  });
});
