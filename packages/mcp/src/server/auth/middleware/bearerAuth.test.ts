import { jest } from '@jest/globals';
import express, { Request, Response } from "express";
import * as net from "node:net";
import type { AuthInfo, OAuthTokenVerifier } from "@modelcontextprotocol/server";
import { requireBearerAuth } from "./bearerAuth.js";
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

  describe("missing-audience warning at construction", () => {
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
      expect(String(warn.mock.calls[0][0])).toMatch(/set audiences/);
    });

    it("does not warn when built from issuers with audiences", () => {
      requireBearerAuth({
        issuers: "https://auth.example.com",
        audiences: "https://api.example.com",
      });
      expect(warn).not.toHaveBeenCalled();
    });

    it("does not warn when the caller supplies its own verifier", () => {
      requireBearerAuth({ verifier: mockVerifier });
      expect(warn).not.toHaveBeenCalled();
    });
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
