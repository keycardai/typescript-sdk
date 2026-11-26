import type { MetadataOptions } from "./types.js";
import {
  AUTHORIZATION_SERVER_PATH, PROTECTED_RESOURCE_PATH, requestTarget, resolveResourceBinding, warnStatelessLegacy,
  zoneIssuers, type ResourceIdentifier,
} from "./resourceBinding.js";

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
  return handleMetadata(request, options);
}

export async function handleMetadata(
  request: Request,
  options: MetadataOptions,
  binding = resolveResourceBinding(options),
  warn = true,
): Promise<Response | null> {
  const issuers = zoneIssuers(binding, options.issuer);
  if (binding.mode === "legacy" && warn) warnStatelessLegacy("handleMetadataRequest");
  const url = new URL(request.url);

  if (binding.mode === "legacy" && request.method === "OPTIONS" && url.pathname.startsWith("/.well-known/")) {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }

  if (binding.mode !== "legacy" && request.method !== "GET" && request.method !== "OPTIONS") {
    return null;
  }
  const matched = (identifier: ResourceIdentifier) => identifier.metadataTarget === requestTarget(request.url);
  let document: { resource: string; authorizationServers: string[] } | undefined;
  if (binding.mode === "legacy" && url.pathname === PROTECTED_RESOURCE_PATH) {
    document = { resource: url.origin, authorizationServers: [options.issuer] };
  } else if (binding.mode === "single" && matched(binding.identifier)) {
    document = { resource: binding.identifier.value, authorizationServers: [options.issuer] };
  } else if (binding.mode === "shared" && matched(binding.identifier)) {
    document = { resource: binding.identifier.value, authorizationServers: [...issuers.values()] };
  } else if (binding.mode === "perZone") {
    const matches = [...binding.entries].filter(([, identifier]) => matched(identifier));
    const entry = matches.length === 1 ? matches[0] : matches.find(([, identifier]) =>
      new URL(identifier.metadataUrl!).host === url.host,
    );
    if (entry) document = { resource: entry[1].value, authorizationServers: [issuers.get(entry[0])!] };
  }

  if (document) {
    if (request.method === "OPTIONS") return preflight();
    return handleProtectedResourceMetadata(document, options);
  }

  const zoneMode = binding.mode === "perZone" || binding.mode === "shared";
  const selectedIssuer = zoneMode
    ? (url.pathname.startsWith(AUTHORIZATION_SERVER_PATH + "/")
      ? issuers.get(url.pathname.slice(AUTHORIZATION_SERVER_PATH.length + 1).split("/")[0]) : undefined)
    : (url.pathname === AUTHORIZATION_SERVER_PATH ? options.issuer : undefined);
  if (selectedIssuer) {
    if (request.method === "OPTIONS") return preflight();
    return handleAuthorizationServerMetadata(selectedIssuer, binding.mode !== "legacy", options.timeoutMs);
  }
  if (url.pathname === "/.well-known/jwks.json" && options.publicJwks) {
    if (request.method === "OPTIONS") return preflight();
    return jsonResponse(options.publicJwks);
  }

  return null;
}

function preflight(): Response {
  return new Response(null, { status: 204, headers: CORS_HEADERS });
}

function handleProtectedResourceMetadata(
  document: { resource: string; authorizationServers: string[] },
  options: MetadataOptions,
): Response {
  const json: Record<string, unknown> = {
    resource: document.resource,
    authorization_servers: document.authorizationServers,
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

  return jsonResponse(json);
}

/** Default timeout for the metadata request to the issuer. */
export const DEFAULT_METADATA_TIMEOUT_MS = 10_000;

async function handleAuthorizationServerMetadata(
  issuer: string,
  preserveBody: boolean,
  timeoutMs = DEFAULT_METADATA_TIMEOUT_MS,
): Promise<Response> {
  let resp: Response;
  try {
    resp = await fetch(issuer + "/.well-known/oauth-authorization-server", {
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch {
    return new Response("Failed to fetch authorization server metadata", {
      status: 502,
      headers: CORS_HEADERS,
    });
  }

  if (!resp.ok) {
    return new Response("Failed to fetch authorization server metadata", {
      status: 502,
      headers: CORS_HEADERS,
    });
  }

  if (preserveBody) {
    return new Response(resp.body, { headers: { "Content-Type": "application/json", ...CORS_HEADERS } });
  }
  return jsonResponse(await resp.json());
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
