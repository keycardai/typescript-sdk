import type { MetadataOptions } from "./types.js";

const CORS_HEADERS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, MCP-Protocol-Version",
};

/**
 * Handles OAuth metadata and JWKS requests for Workers.
 *
 * Returns a `Response` for:
 * - `/.well-known/oauth-protected-resource`
 * - `/.well-known/oauth-authorization-server`
 * - `/.well-known/jwks.json` (if `publicJwks` is provided)
 *
 * Returns `null` if the request path doesn't match any metadata endpoint.
 */
export async function handleMetadataRequest(
  request: Request,
  options: MetadataOptions,
): Promise<Response | null> {
  const url = new URL(request.url);

  // CORS preflight for metadata endpoints
  if (request.method === "OPTIONS" && url.pathname.startsWith("/.well-known/")) {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }

  if (url.pathname === "/.well-known/oauth-protected-resource") {
    return handleProtectedResourceMetadata(request, url, options);
  }

  if (url.pathname === "/.well-known/oauth-authorization-server") {
    return handleAuthorizationServerMetadata(url, options);
  }

  if (url.pathname === "/.well-known/jwks.json" && options.publicJwks) {
    return jsonResponse(options.publicJwks);
  }

  return null;
}

function handleProtectedResourceMetadata(
  request: Request,
  url: URL,
  options: MetadataOptions,
): Response {
  const baseUrl = url.origin;
  const resource = url.origin + url.pathname.replace(/^\/.well-known\/oauth-protected-resource/, "") || baseUrl;

  const json: Record<string, unknown> = {
    resource: baseUrl,
    authorization_servers: [options.issuer],
  };

  if (options.scopesSupported) {
    json.scopes_supported = options.scopesSupported;
  }
  if (options.resourceName) {
    json.resource_name = options.resourceName;
  }
  if (options.serviceDocumentationUrl) {
    json.resource_documentation = options.serviceDocumentationUrl;
  }

  // MCP protocol version 2025-03-26 backwards compat:
  // rewrite authorization_servers to the base URL
  const mcpVersion = request.headers.get("mcp-protocol-version");
  if (mcpVersion === "2025-03-26") {
    json.authorization_servers = [baseUrl];
  }

  return jsonResponse(json);
}

async function handleAuthorizationServerMetadata(
  url: URL,
  options: MetadataOptions,
): Promise<Response> {
  const resp = await fetch(
    options.issuer + "/.well-known/oauth-authorization-server",
  );

  if (!resp.ok) {
    return new Response("Failed to fetch authorization server metadata", {
      status: 502,
      headers: CORS_HEADERS,
    });
  }

  const json = (await resp.json()) as Record<string, unknown>;
  const baseUrl = url.origin;

  // Rewrite authorization_endpoint to include ?resource= so STS knows
  // which resource is being requested
  if (typeof json.authorization_endpoint === "string") {
    const authorizationUrl = new URL(json.authorization_endpoint);
    authorizationUrl.searchParams.set("resource", baseUrl);
    json.authorization_endpoint = authorizationUrl.toString();
  }

  return jsonResponse(json);
}

function jsonResponse(data: unknown): Response {
  return new Response(JSON.stringify(data), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      ...CORS_HEADERS,
    },
  });
}
