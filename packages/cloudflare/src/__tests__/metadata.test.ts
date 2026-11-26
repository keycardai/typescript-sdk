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

  it("metadata rows 1 and 7: publishes the exact configured identifier independent of the request origin", async () => {
    for (const [resourceIdentifier, suffix] of [
      ["https://example.com", ""],
      ["https://example.com/mcp?q=1", "/mcp?q=1"],
    ]) {
      const request = new Request("http://internal.example/.well-known/oauth-protected-resource" + suffix);
      const result = await handleMetadataRequest(request, { ...baseOptions, resourceIdentifier });
      expect(result?.status).toBe(200);
      expect(await result?.json()).toMatchObject({ resource: resourceIdentifier, authorization_servers: [baseOptions.issuer] });
    }
  });

  it("metadata rows 8d and 8e: validates options first and skips only the verifier-only document", async () => {
    const warn = jest.spyOn(console, "warn").mockImplementation(() => {});
    try {
      for (const flags of [{ allowAnyAudience: true }, { multiResource: true }]) {
        const options = { ...baseOptions, ...flags, publicJwks: { keys: [] } };
        expect(await handleMetadataRequest(new Request("https://example.com/.well-known/oauth-protected-resource"), options)).toBeNull();
        expect((await handleMetadataRequest(new Request("https://example.com/.well-known/jwks.json"), options))?.status).toBe(200);
      }
      expect(warn).not.toHaveBeenCalled();
      await expect(handleMetadataRequest(new Request("https://example.com/non-metadata"), {
        ...baseOptions, allowAnyAudience: true, multiResource: true,
      })).rejects.toMatchObject({ name: "ConfigurationError" });
    } finally {
      warn.mockRestore();
    }
  });

  it("metadata rows 4a, 4b, 9a, 9c and integration 2: only configured zones are discoverable", async () => {
    const a = "https://example.com/a/mcp";
    const b = "https://example.com/b/mcp";
    const options = { issuer: "https://keycard.cloud:9443", resourceIdentifiersByZone: { a, b } };
    const upstream = '{\n  "authorization_endpoint": "https://auth.example.com/authorize?resource=stale&keep=1"\n}\n';
    const fetch = jest.spyOn(globalThis, "fetch").mockImplementation(async () => new Response(upstream));
    try {
      for (const [zone, resource] of Object.entries(options.resourceIdentifiersByZone)) {
        const issuer = `https://${zone}.keycard.cloud:9443`;
        const result = await handleMetadataRequest(new Request(`https://example.com/.well-known/oauth-protected-resource/${zone}/mcp`), options);
        expect(await result?.json()).toEqual({ resource, authorization_servers: [issuer] });
        const metadata = await handleMetadataRequest(new Request(`https://example.com/.well-known/oauth-authorization-server/${zone}`), options);
        expect(await metadata?.text()).toBe(upstream);
        expect(fetch).toHaveBeenLastCalledWith(issuer + "/.well-known/oauth-authorization-server", expect.anything());
      }
      for (const suffix of ["", "/c"]) {
        expect(await handleMetadataRequest(new Request("https://example.com/.well-known/oauth-authorization-server" + suffix), options)).toBeNull();
      }
      expect(fetch).toHaveBeenCalledTimes(2);
      const shared = await handleMetadataRequest(new Request("https://example.com/.well-known/oauth-protected-resource/a/mcp"), {
        ...options, multiResource: true, resourceIdentifiersByZone: { a, b: a },
      });
      expect(await shared?.json()).toEqual({ resource: a, authorization_servers: ["https://a.keycard.cloud:9443", "https://b.keycard.cloud:9443"] });
    } finally {
      fetch.mockRestore();
    }
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

  it("returns the configured issuer in authorization_servers regardless of the MCP-Protocol-Version header", async () => {
    const request = new Request("https://example.com/.well-known/oauth-protected-resource", {
      headers: { "mcp-protocol-version": "2025-03-26" },
    });
    const result = await handleMetadataRequest(request, baseOptions);
    const json = await result!.json();

    expect(json.authorization_servers).toEqual(["https://z_abc123.keycard.cloud"]);
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

      // The upstream document is returned unmodified
      expect(json).toEqual(mockMetadata);
      expect(json.authorization_endpoint).toBe("https://z_abc123.keycard.cloud/oauth/authorize");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("passes an authorization_endpoint with an existing query through unchanged", async () => {
    const mockMetadata = {
      issuer: "https://z_abc123.keycard.cloud",
      authorization_endpoint: "https://z_abc123.keycard.cloud/oauth/authorize?resource=stale&keep=1",
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

      expect(json).toEqual(mockMetadata);
      expect(json.authorization_endpoint).toBe(
        "https://z_abc123.keycard.cloud/oauth/authorize?resource=stale&keep=1",
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
