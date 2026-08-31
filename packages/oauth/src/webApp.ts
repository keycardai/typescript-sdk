import base64url from "./base64url.js";
import { fetchAuthorizationServerMetadata, type OAuthAuthorizationServerMetadata } from "./discovery.js";
import { AuthorizationDeniedError, OAuthError, StateMismatchError } from "./errors.js";
import { buildAuthorizeUrl, exchangeAuthorizationCode, generatePkcePair } from "./pkce.js";
import type { TokenResponse } from "./tokenExchange.js";

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
}

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
    ?? await fetchAuthorizationServerMetadata(issuer, { signal: options.signal });
  if (!metadata.authorization_endpoint) {
    throw new Error(
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
  });
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
