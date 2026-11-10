import { requestSignal } from "./requestSignal.js";
import base64url from "./base64url.js";
import { basicAuthorization } from "./basicAuthorization.js";
import { fetchAuthorizationServerMetadata, type OAuthAuthorizationServerMetadata } from "./discovery.js";
import {
  AuthorizationDeniedError,
  ConfigurationError,
  isPermanentErrorCode,
  OAuthError,
  RefreshGrantError,
  StateMismatchError,
} from "./errors.js";
import { requireClientAuthentication, type ApplicationCredential, type ClientAuthenticator } from "./credentials.js";
import { buildAuthorizeUrl, exchangeAuthorizationCode, generatePkcePair } from "./pkce.js";
import { deserializeTokenResponse, type TokenResponse } from "./tokenExchange.js";

// =============================================================================
// Stateless web-app authorization-code flow with PKCE
// =============================================================================

export interface BeginAuthorizationOptions {
  clientId: string;
  /** Registered redirect URI handled by the web application. */
  redirectUri: string;
  /**
   * Protected resources the authorization is targeting. Each entry is sent as
   * its own RFC 8707 `resource` parameter, so one authorization can cover
   * several resources and the issued token's audience covers all of them.
   */
  resources?: readonly string[];
  scopes?: readonly string[];
  /** Pre-discovered metadata. When set, no discovery request is made. */
  metadata?: OAuthAuthorizationServerMetadata;
  signal?: AbortSignal;
  /** Timeout in milliseconds for each request to the authorization server (default 10 seconds; 0 disables). */
  timeoutMs?: number;
}

export interface AuthorizationRedirect {
  /** The authorization URL to redirect the user's browser to. */
  url: string;
  /** Generated CSRF value to store until the callback. */
  state: string;
  /** Generated PKCE verifier to store until the callback; never send it to the browser. */
  codeVerifier: string;
  /**
   * The resources the authorization request was scoped to. They are not needed
   * to redeem the code — the authorization server derives the issued token's
   * audience from the code itself — but applications commonly need to know
   * which resources a session was authorized for.
   */
  resources: string[];
}

export interface CompleteAuthorizationOptions {
  /** Query parameters the callback route received. */
  callbackParams: URLSearchParams | Record<string, string>;
  /** The `state` stored at the begin step. */
  state: string;
  /** The `codeVerifier` stored at the begin step. */
  codeVerifier: string;
  clientId: string;
  /** The same registered redirect URI used at the begin step. */
  redirectUri: string;
  /** Client secret for confidential clients. Public clients omit it. */
  clientSecret?: string;
  /** Pre-discovered metadata. When set, no discovery request is made. */
  metadata?: OAuthAuthorizationServerMetadata;
  signal?: AbortSignal;
  /** Timeout in milliseconds for each request to the authorization server (default 10 seconds; 0 disables). */
  timeoutMs?: number;
}

/**
 * Set either `clientId`, with `clientSecret` for a confidential client, or
 * `credential`. Setting both, or passing a credential without
 * `clientAuthentication`, throws `ConfigurationError` before any request.
 */
export type RefreshAuthorizationOptions = (
  | {
      /** The client the grant was issued to. */
      clientId: string;
      /** Client secret for confidential clients. Public clients omit it. */
      clientSecret?: string;
      credential?: never;
    }
  | {
      /** Authenticates the refresh with the credential's `clientAuthentication`. */
      credential: ApplicationCredential;
      clientId?: never;
      clientSecret?: never;
    }
) & {
  /** The `refresh_token` a previous token response returned. */
  refreshToken: string;
  /**
   * RFC 8707 resource indicators, one `resource` parameter per entry, to
   * narrow the refreshed token to a subset of the granted resources.
   */
  resources?: readonly string[];
  /** Requested scopes, to narrow the refreshed token to a subset of the granted scopes. */
  scopes?: readonly string[];
  /** Pre-discovered metadata. When set, no discovery request is made. */
  metadata?: OAuthAuthorizationServerMetadata;
  signal?: AbortSignal;
  /** Timeout in milliseconds for each request to the authorization server (default 10 seconds; 0 disables). */
  timeoutMs?: number;
};

/**
 * Begin a web-app authorization-code-with-PKCE flow.
 *
 * For applications that own a registered redirect URI and receive the callback
 * on their own route, where the loopback listener `authenticate()` runs is
 * wrong. Generates the PKCE pair and a CSRF `state`, resolves the
 * `authorization_endpoint` by discovery, and builds the authorization URL with
 * one `resource` parameter per entry of `resources`.
 *
 * The SDK holds no state between begin and complete: where `state` and
 * `codeVerifier` live between the redirect and the callback (a session, a
 * signed cookie) is the application's concern, which is what makes the flow
 * safe under concurrent sign-ins and multi-process servers.
 */
export async function beginAuthorization(
  issuer: string,
  options: BeginAuthorizationOptions,
): Promise<AuthorizationRedirect> {
  const metadata = options.metadata
    ?? await fetchAuthorizationServerMetadata(issuer, {
      signal: options.signal,
      timeoutMs: options.timeoutMs,
    });
  if (!metadata.authorization_endpoint) {
    throw new ConfigurationError(
      `Authorization server "${issuer}" does not advertise an authorization_endpoint`,
    );
  }

  const { codeVerifier, codeChallenge } = await generatePkcePair("S256");

  const stateBytes = new Uint8Array(32);
  crypto.getRandomValues(stateBytes);
  const state = base64url.encode(stateBytes.buffer as ArrayBuffer);

  const resources = [...options.resources ?? []];
  const url = buildAuthorizeUrl(metadata.authorization_endpoint, {
    clientId: options.clientId,
    redirectUri: options.redirectUri,
    codeChallenge,
    state,
    scope: options.scopes && options.scopes.length > 0 ? options.scopes.join(" ") : undefined,
    resources,
  });

  return { url, state, codeVerifier, resources };
}

/**
 * Complete a web-app authorization-code-with-PKCE flow from the callback route.
 *
 * Callback validation happens before discovery or any token request: a
 * callback carrying `error` throws `AuthorizationDeniedError`, a missing or
 * non-matching `state` throws `StateMismatchError`, and a missing `code`
 * throws `OAuthError("invalid_request")`.
 *
 * No RFC 8707 `resource` parameter is sent on the token request: the
 * authorization server derives the issued token's audience from the
 * authorization code, which already records the resources authorized at the
 * begin step.
 */
export async function completeAuthorization(
  issuer: string,
  options: CompleteAuthorizationOptions,
): Promise<TokenResponse> {
  const params = options.callbackParams instanceof URLSearchParams
    ? options.callbackParams
    : new URLSearchParams(options.callbackParams);

  const error = params.get("error");
  if (error) {
    throw new AuthorizationDeniedError(
      error,
      params.get("error_description") ?? undefined,
      params.get("error_uri") ?? undefined,
    );
  }

  const callbackState = params.get("state");
  if (callbackState === null || !timingSafeEqual(callbackState, options.state)) {
    throw new StateMismatchError();
  }

  const code = params.get("code");
  if (!code) {
    throw new OAuthError(
      "invalid_request",
      "Authorization callback is missing 'code'",
    );
  }

  return exchangeAuthorizationCode(issuer, code, {
    codeVerifier: options.codeVerifier,
    redirectUri: options.redirectUri,
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    metadata: options.metadata,
    signal: options.signal,
    timeoutMs: options.timeoutMs,
  });
}

/**
 * Redeem a refresh token for a new token (RFC 6749 §6).
 *
 * POSTs `grant_type=refresh_token` to the token endpoint, authenticating the
 * client the way the grant that issued the refresh token did: `client_id` in
 * the body for a public client, HTTP Basic for a confidential one, or the
 * headers and form fields from `credential.clientAuthentication`. When the
 * response has a `refreshToken`, the server rotated it. Store the new value
 * in place of the old one. The SDK does not keep the refresh token.
 *
 * Throws `ConfigurationError` before any request when the client options
 * are not valid, and before the refresh request when the metadata has no
 * `token_endpoint`. Errors from discovery and from the credential's
 * `clientAuthentication` are thrown as is. A failed refresh request throws
 * `RefreshGrantError`, except a 2xx response without `access_token`, which
 * throws `OAuthError` `invalid_response`. `invalid_grant` is not retryable
 * and means the user must authorize again. A transport failure or a 5xx is
 * retryable and leaves the refresh token usable.
 */
export async function refreshAuthorization(
  issuer: string,
  options: RefreshAuthorizationOptions,
): Promise<TokenResponse> {
  let client: { credential: ClientAuthenticator } | { clientId: string; clientSecret?: string };
  if (options.credential !== undefined) {
    if (options.clientId !== undefined || options.clientSecret !== undefined) {
      throw new ConfigurationError(
        "refreshAuthorization: set either credential or clientId and clientSecret, not both",
      );
    }
    client = { credential: requireClientAuthentication(options.credential, "refreshAuthorization") };
  } else if (typeof options.clientId === "string" && options.clientId) {
    client = { clientId: options.clientId, clientSecret: options.clientSecret };
  } else {
    throw new ConfigurationError("refreshAuthorization: clientId or credential is required");
  }

  const metadata = options.metadata
    ?? await fetchAuthorizationServerMetadata(issuer, {
      signal: options.signal,
      timeoutMs: options.timeoutMs,
    });
  if (!metadata.token_endpoint) {
    throw new ConfigurationError(
      `Authorization server "${issuer}" does not advertise a token_endpoint`,
    );
  }

  const params = new URLSearchParams();
  params.set("grant_type", "refresh_token");
  params.set("refresh_token", options.refreshToken);
  if (options.scopes && options.scopes.length > 0) {
    params.set("scope", options.scopes.join(" "));
  }
  for (const resource of options.resources ?? []) {
    params.append("resource", resource);
  }

  const headers: Record<string, string> = {
    "Content-Type": "application/x-www-form-urlencoded",
  };
  if ("credential" in client) {
    const auth = await client.credential.clientAuthentication(issuer, metadata.token_endpoint);
    Object.assign(headers, auth.headers);
    for (const [name, value] of Object.entries(auth.form)) params.set(name, value);
  } else if (client.clientSecret) {
    headers["Authorization"] = basicAuthorization(client.clientId, client.clientSecret);
  } else {
    params.set("client_id", client.clientId);
  }

  let response: Response;
  try {
    response = await fetch(metadata.token_endpoint, {
      method: "POST",
      headers,
      body: params.toString(),
      signal: requestSignal(options.signal, options.timeoutMs),
    });
  } catch (cause) {
    throw new RefreshGrantError(
      "invalid_response",
      `Refresh token request failed: ${cause instanceof Error ? cause.message : String(cause)}`,
      { retryable: true, cause },
    );
  }

  if (!response.ok) {
    const retryable = response.status >= 500 || response.status === 429;
    let errorBody: Record<string, unknown> | null = null;
    try {
      const json = await response.json() as unknown;
      if (json && typeof json === "object" && !Array.isArray(json)) {
        errorBody = json as Record<string, unknown>;
      }
    } catch {
      // non-JSON error body: fall through to the generic error
    }
    if (errorBody && typeof errorBody.error === "string") {
      const description = typeof errorBody.error_description === "string"
        ? errorBody.error_description
        : errorBody.error;
      const errorUri = typeof errorBody.error_uri === "string" ? errorBody.error_uri : undefined;
      throw new RefreshGrantError(errorBody.error, description, {
        retryable: retryable && !isPermanentErrorCode(errorBody.error),
        status: response.status,
        errorUri,
      });
    }
    throw new RefreshGrantError(
      "invalid_response",
      `Refresh token request failed (HTTP ${response.status})`,
      { retryable, status: response.status },
    );
  }

  let json: unknown;
  try {
    json = await response.json();
  } catch (cause) {
    throw new RefreshGrantError(
      "invalid_response",
      "Token endpoint response is not valid JSON",
      { retryable: false, status: response.status, cause },
    );
  }
  if (!json || typeof json !== "object" || Array.isArray(json)) {
    throw new RefreshGrantError(
      "invalid_response",
      "Token endpoint response is not a valid JSON object",
      { retryable: false, status: response.status },
    );
  }
  return deserializeTokenResponse(json as Record<string, unknown>);
}

/** Compare two strings without leaking their common prefix length via timing. */
function timingSafeEqual(a: string, b: string): boolean {
  const left = new TextEncoder().encode(a);
  const right = new TextEncoder().encode(b);
  let diff = left.length ^ right.length;
  for (let i = 0; i < left.length; i++) {
    diff |= left[i] ^ right[i % (right.length || 1)];
  }
  return diff === 0;
}
