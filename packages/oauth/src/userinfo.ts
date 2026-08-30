import { fetchAuthorizationServerMetadata, type OAuthAuthorizationServerMetadata } from "./discovery.js";
import { HTTPError, InsufficientScopeError, InvalidTokenError, OAuthError } from "./errors.js";

/**
 * Claims returned by the UserInfo endpoint (OIDC Core 1.0 §5.3).
 *
 * Claims are returned exactly as the provider sent them: nothing is filtered
 * to a known set. `sub` is the only claim OIDC requires and is validated
 * present.
 */
export interface UserInfoResponse {
  sub: string;
  /** The full claims document as returned, `sub` included. */
  claims: Record<string, unknown>;
}

export interface FetchUserInfoOptions {
  /** Pre-discovered metadata. When set, no discovery request is made. */
  metadata?: OAuthAuthorizationServerMetadata;
  signal?: AbortSignal;
}

/** Extract the RFC 6750 §3 `error` code from a `WWW-Authenticate` challenge. */
function challengeError(wwwAuthenticate: string | null): string {
  if (!wwwAuthenticate) return "invalid_token";
  const match = /error\s*=\s*"?([^",\s]+)"?/.exec(wwwAuthenticate);
  return match ? match[1] : "invalid_token";
}

/**
 * Fetch the signed-in user's identity claims from the issuer's UserInfo
 * endpoint (OIDC Core 1.0 §5.3).
 *
 * Keycard zone access tokens are authorization-only: identity claims such as
 * `email` or `groups` are not in the token and live behind the issuer's
 * `userinfo_endpoint`. The endpoint is resolved by discovery unless
 * `options.metadata` is supplied, in which case the caller owns caching and
 * refreshing that metadata.
 *
 * The access token is presented as a Bearer credential; the request carries no
 * client authentication, because UserInfo authenticates the user, not the
 * client. Signed (`application/jwt`) responses are not supported. Nothing is
 * cached: caching claims per token is the caller's concern.
 */
export async function fetchUserInfo(
  issuer: string,
  accessToken: string,
  options: FetchUserInfoOptions = {},
): Promise<UserInfoResponse> {
  const metadata = options.metadata
    ?? await fetchAuthorizationServerMetadata(issuer, { signal: options.signal });

  if (!metadata.userinfo_endpoint) {
    throw new Error(
      `Authorization server "${issuer}" does not advertise a userinfo_endpoint`,
    );
  }

  const response = await fetch(metadata.userinfo_endpoint, {
    method: "GET",
    headers: {
      Accept: "application/json",
      Authorization: `Bearer ${accessToken}`,
    },
    signal: options.signal,
  });

  if (response.status === 401) {
    const errorCode = challengeError(response.headers.get("www-authenticate"));
    const message =
      `UserInfo request rejected with "${errorCode}": the access token is expired, ` +
      "revoked, or not accepted at the UserInfo endpoint";
    if (errorCode === "insufficient_scope") {
      throw new InsufficientScopeError(message);
    }
    if (errorCode === "invalid_token") {
      throw new InvalidTokenError(message);
    }
    throw new OAuthError(errorCode, message);
  }

  if (!response.ok) {
    throw new HTTPError(
      `UserInfo request to "${metadata.userinfo_endpoint}" failed (HTTP ${response.status})`,
    );
  }

  const contentType = response.headers.get("content-type") ?? "";
  if (contentType.toLowerCase().includes("application/jwt")) {
    throw new OAuthError(
      "invalid_response",
      `Unsupported UserInfo response content type "${contentType}": signed and ` +
      "encrypted UserInfo responses are not supported",
    );
  }

  let json: unknown;
  try {
    json = await response.json() as unknown;
  } catch {
    throw new OAuthError("invalid_response", "Malformed JSON in UserInfo response");
  }
  if (!json || typeof json !== "object" || Array.isArray(json)) {
    throw new OAuthError(
      "invalid_response",
      "UserInfo response must be a JSON object of claims",
    );
  }

  const claims = json as Record<string, unknown>;
  const sub = claims.sub;
  if (typeof sub !== "string" || sub.length === 0) {
    throw new OAuthError(
      "invalid_response",
      "UserInfo response must include a 'sub' claim",
    );
  }

  return { sub, claims };
}
