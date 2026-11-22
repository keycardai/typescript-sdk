import { ConfigurationError } from "./errors.js";
import { ClientSecret } from "./server/clientSecret.js";
import { requestSignal } from "./requestSignal.js";
import { authenticate, type AuthenticateOptions } from "./pkce.js";
import type { TokenResponse } from "./tokenExchange.js";

// =============================================================================
// WWW-Authenticate challenge resolution (RFC 9728)
// =============================================================================

export interface ResolveIssuerFromChallengeOptions {
  signal?: AbortSignal;
  /** Timeout in milliseconds for each request to the authorization server (default 10 seconds; 0 disables). */
  timeoutMs?: number;
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

  const response = await fetch(metadataUrl, {
    signal: requestSignal(options.signal, options.timeoutMs),
  });
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

export interface AuthenticateFromChallengeOptions extends AuthenticateOptions {
  /**
   * The issuers the caller trusts. The issuer resolved from the challenge
   * must equal one of them, compared without a trailing slash. Required when
   * `clientSecret` or `credential` is set, so client authentication only
   * goes to an issuer the caller chose. Optional for a public client; when
   * set, it is enforced the same way. When unset and `credential` is a
   * multi-zone `ClientSecret`, the credential's zone issuers are the
   * allow-list.
   */
  allowedIssuers?: readonly string[];
}

function withoutTrailingSlash(value: string): string {
  return value.replace(/\/$/, "");
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
 * The resource names the issuer, so client authentication (`clientSecret`
 * or `credential`) requires `allowedIssuers`. A multi-zone `ClientSecret`
 * credential counts as the pin: with `allowedIssuers` unset, its zone
 * issuers are the allow-list. Throws `ConfigurationError`
 * before any request when client authentication is set without
 * `allowedIssuers`, and after the metadata fetch, before any request to the
 * resolved issuer, when that issuer is not in `allowedIssuers`.
 *
 * **Requires Node.js.** Uses `node:http` and `node:child_process` via
 * dynamic import. Importing this module is safe in any runtime; only
 * *calling* `authenticateFromChallenge()` requires Node.js.
 */
export async function authenticateFromChallenge(
  wwwAuthenticateHeader: string,
  options: AuthenticateFromChallengeOptions,
): Promise<TokenResponse> {
  const { allowedIssuers, ...authenticateOptions } = options;
  const explicit = allowedIssuers !== undefined && allowedIssuers.length > 0;
  const zoneIssuers =
    options.credential instanceof ClientSecret ? options.credential.zoneIssuers : undefined;
  const allowList = explicit ? allowedIssuers : zoneIssuers;
  const sendsClientAuthentication =
    options.clientSecret !== undefined || options.credential !== undefined;
  if (sendsClientAuthentication && allowList === undefined) {
    throw new ConfigurationError(
      "authenticateFromChallenge: set allowedIssuers to send clientSecret or credential to an issuer resolved from a challenge",
    );
  }

  const { issuer, resource } = await resolveIssuerFromChallenge(wwwAuthenticateHeader);
  if (allowList !== undefined) {
    const resolved = withoutTrailingSlash(issuer);
    if (!allowList.some((allowed) => withoutTrailingSlash(allowed) === resolved)) {
      throw new ConfigurationError(
        explicit
          ? `authenticateFromChallenge: the challenge resolved issuer "${issuer}", which is not in allowedIssuers`
          : `authenticateFromChallenge: the challenge resolved issuer "${issuer}", which is not one of the multi-zone ClientSecret's zone issuers`,
      );
    }
  }

  return authenticate(issuer, {
    ...authenticateOptions,
    resource: options.resource ?? resource,
  });
}
