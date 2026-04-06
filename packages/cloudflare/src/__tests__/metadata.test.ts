import { describe, it, expect, jest, beforeEach } from "@jest/globals";
import { handleMetadataRequest } from "../metadata.js";

describe("handleMetadataRequest", () => {
  const baseOptions = {
    issuer: "https://z_abc123.keycard.cloud",
    scopesSupported: ["mcp:tools"],
    resourceName: "Test MCP Server",
  };

  it("returns null for non-metadata paths", async () => {
    const request = new Request("https://example.com/mcp");
    const result = await handleMetadataRequest(request, baseOptions);
    expect(result).toBeNull();
  });

  it("returns protected resource metadata", async () => {
    const request = new Request("https://example.com/.well-known/oauth-protected-resource");
    const result = await handleMetadataRequest(request, baseOptions);

    expect(result).not.toBeNull();
    expect(result!.status).toBe(200);

    const json = await result!.json();
    expect(json.resource).toBe("https://example.com");
    expect(json.authorization_servers).toEqual(["https://z_abc123.keycard.cloud"]);
    expect(json.scopes_supported).toEqual(["mcp:tools"]);
    expect(json.resource_name).toBe("Test MCP Server");
  });

  it("handles MCP protocol version 2025-03-26 backwards compat", async () => {
    const request = new Request("https://example.com/.well-known/oauth-protected-resource", {
      headers: { "mcp-protocol-version": "2025-03-26" },
    });
    const result = await handleMetadataRequest(request, baseOptions);
    const json = await result!.json();

    // Should rewrite authorization_servers to the base URL
    expect(json.authorization_servers).toEqual(["https://example.com"]);
  });

  it("returns CORS headers", async () => {
    const request = new Request("https://example.com/.well-known/oauth-protected-resource");
    const result = await handleMetadataRequest(request, baseOptions);

    expect(result!.headers.get("Access-Control-Allow-Origin")).toBe("*");
  });

  it("handles CORS preflight for well-known paths", async () => {
    const request = new Request("https://example.com/.well-known/oauth-protected-resource", {
      method: "OPTIONS",
    });
    const result = await handleMetadataRequest(request, baseOptions);

    expect(result).not.toBeNull();
    expect(result!.status).toBe(204);
    expect(result!.headers.get("Access-Control-Allow-Origin")).toBe("*");
  });

  it("serves JWKS when publicJwks is configured", async () => {
    const publicJwks = { keys: [{ kty: "RSA", n: "abc", e: "AQAB", kid: "test-key" }] };
    const request = new Request("https://example.com/.well-known/jwks.json");
    const result = await handleMetadataRequest(request, { ...baseOptions, publicJwks });

    expect(result).not.toBeNull();
    const json = await result!.json();
    expect(json.keys).toHaveLength(1);
    expect(json.keys[0].kid).toBe("test-key");
  });

  it("returns null for JWKS when publicJwks is not configured", async () => {
    const request = new Request("https://example.com/.well-known/jwks.json");
    const result = await handleMetadataRequest(request, baseOptions);
    expect(result).toBeNull();
  });

  it("proxies authorization server metadata", async () => {
    const mockMetadata = {
      issuer: "https://z_abc123.keycard.cloud",
      authorization_endpoint: "https://z_abc123.keycard.cloud/oauth/authorize",
      token_endpoint: "https://z_abc123.keycard.cloud/oauth/token",
    };

    const originalFetch = globalThis.fetch;
    globalThis.fetch = jest.fn<typeof fetch>().mockResolvedValue(
      new Response(JSON.stringify(mockMetadata), { status: 200 }),
    );

    try {
      const request = new Request("https://example.com/.well-known/oauth-authorization-server");
      const result = await handleMetadataRequest(request, baseOptions);

      expect(result).not.toBeNull();
      const json = await result!.json();

      // Should rewrite authorization_endpoint to include ?resource=
      expect(json.authorization_endpoint).toContain("resource=https%3A%2F%2Fexample.com");
      expect(json.token_endpoint).toBe("https://z_abc123.keycard.cloud/oauth/token");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
