import { authenticate, type AuthenticateOptions } from "./pkce.js";
import type { TokenResponse } from "./tokenExchange.js";

// =============================================================================
// WWW-Authenticate challenge resolution (RFC 9728)
// =============================================================================

export interface ResolveIssuerFromChallengeOptions {
  signal?: AbortSignal;
}

export interface ResolvedChallenge {
  /** The authorization server issuer URL (first entry of `authorization_servers`). */
  issuer: string;
  /** The protected resource identifier from the metadata document, when present. */
  resource?: string;
}

/**
 * Extract the `resource_metadata` parameter value from a `WWW-Authenticate`
 * header (RFC 9728 §5.1). Handles quoted values alongside other challenge
 * parameters (e.g. `realm`, `error`). Returns undefined when absent.
 */
function extractResourceMetadataUrl(wwwAuthenticateHeader: string): string | undefined {
  // Quoted form: resource_metadata="https://..."
  const quoted = /resource_metadata\s*=\s*"([^"]+)"/.exec(wwwAuthenticateHeader);
  if (quoted) {
    return quoted[1];
  }
  // Unquoted token form: resource_metadata=https://... (terminated by comma,
  // whitespace, or end of header).
  const unquoted = /resource_metadata\s*=\s*([^",\s]+)/.exec(wwwAuthenticateHeader);
  return unquoted ? unquoted[1] : undefined;
}

/**
 * Resolve the authorization server issuer from a `WWW-Authenticate` challenge
 * (RFC 9728).
 *
 * Parses the `resource_metadata` URL out of the header, fetches the protected
 * resource metadata document, and returns the first entry of its
 * `authorization_servers` array as the issuer, along with the document's
 * `resource` identifier when present.
 *
 * Throws an `Error` when the header has no `resource_metadata` parameter, the
 * metadata fetch fails, or the document is missing a valid
 * `authorization_servers` array.
 */
export async function resolveIssuerFromChallenge(
  wwwAuthenticateHeader: string,
  options: ResolveIssuerFromChallengeOptions = {},
): Promise<ResolvedChallenge> {
  const metadataUrl = extractResourceMetadataUrl(wwwAuthenticateHeader);
  if (!metadataUrl) {
    throw new Error(
      "WWW-Authenticate header does not contain a resource_metadata parameter (RFC 9728)",
    );
  }

  const response = await fetch(metadataUrl, { signal: options.signal });
  if (!response.ok) {
    throw new Error(
      `Failed to fetch protected resource metadata from "${metadataUrl}" (HTTP ${response.status})`,
    );
  }

  let json: unknown;
  try {
    json = await response.json() as unknown;
  } catch {
    throw new Error(
      `Protected resource metadata at "${metadataUrl}" is not valid JSON`,
    );
  }
  if (!json || typeof json !== "object" || Array.isArray(json)) {
    throw new Error(
      `Protected resource metadata at "${metadataUrl}" is not a JSON object`,
    );
  }
  const document = json as Record<string, unknown>;

  const authorizationServers = document.authorization_servers;
  if (
    !Array.isArray(authorizationServers) ||
    authorizationServers.length === 0 ||
    !authorizationServers.every((entry): entry is string => typeof entry === "string")
  ) {
    throw new Error(
      `Protected resource metadata at "${metadataUrl}" does not contain a non-empty authorization_servers array`,
    );
  }

  return {
    issuer: authorizationServers[0],
    resource: typeof document.resource === "string" ? document.resource : undefined,
  };
}

/**
 * Full authorization-code-with-PKCE flow driven by a `WWW-Authenticate`
 * challenge from a protected resource.
 *
 * Resolves the authorization server issuer from the challenge's
 * `resource_metadata` document (RFC 9728) via `resolveIssuerFromChallenge`,
 * then runs `authenticate()` against it. When the caller does not set
 * `options.resource`, it defaults to the `resource` identifier from the
 * metadata document, scoping the issued token's audience to that resource.
 *
 * **Requires Node.js.** Uses `node:http` and `node:child_process` via
 * dynamic import. Importing this module is safe in any runtime; only
 * *calling* `authenticateFromChallenge()` requires Node.js.
 */
export async function authenticateFromChallenge(
  wwwAuthenticateHeader: string,
  options: AuthenticateOptions,
): Promise<TokenResponse> {
  const { issuer, resource } = await resolveIssuerFromChallenge(wwwAuthenticateHeader);
  return authenticate(issuer, {
    ...options,
    resource: options.resource ?? resource,
  });
}
