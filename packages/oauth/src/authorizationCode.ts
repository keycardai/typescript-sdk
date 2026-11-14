// Internal: not exported from the package. The public entry points are
// `exchangeAuthorizationCode` (`./pkce`) and `completeAuthorization` (`./webApp`).
import { requestSignal } from "./requestSignal.js";
import { fetchAuthorizationServerMetadata, type OAuthAuthorizationServerMetadata } from "./discovery.js";
import { ConfigurationError, OAuthError } from "./errors.js";
import { addClientAuthentication, type TokenClient } from "./tokenClient.js";
import { deserializeTokenResponse, type TokenResponse } from "./tokenExchange.js";

/** The parts of a code redemption besides the code and the client. */
export interface RedeemAuthorizationCodeOptions {
  codeVerifier: string;
  redirectUri: string;
  /** RFC 8707 resource indicator. */
  resource?: string;
  /** Pre-discovered metadata. When set, no discovery request is made. */
  metadata?: OAuthAuthorizationServerMetadata;
  signal?: AbortSignal;
  /** Timeout in milliseconds for each request to the authorization server. */
  timeoutMs?: number;
}

/**
 * The token request of `exchangeAuthorizationCode`, shared with
 * `completeAuthorization`. Authenticates as `client`, or sends no client
 * authentication when `client` is undefined.
 */
export async function redeemAuthorizationCode(
  issuer: string,
  code: string,
  client: TokenClient | undefined,
  options: RedeemAuthorizationCodeOptions,
): Promise<TokenResponse> {
  const metadata = options.metadata ?? await fetchAuthorizationServerMetadata(issuer, {
    signal: options.signal,
    timeoutMs: options.timeoutMs,
  });
  if (!metadata.token_endpoint) {
    throw new ConfigurationError(
      `Authorization server "${issuer}" does not advertise a token_endpoint`,
    );
  }

  const params = new URLSearchParams();
  params.set("grant_type", "authorization_code");
  params.set("code", code);
  params.set("code_verifier", options.codeVerifier);
  params.set("redirect_uri", options.redirectUri);
  if (options.resource) params.set("resource", options.resource);

  const headers: Record<string, string> = {
    "Content-Type": "application/x-www-form-urlencoded",
  };
  if (client) {
    await addClientAuthentication(client, issuer, metadata.token_endpoint, headers, params);
  }

  const response = await fetch(metadata.token_endpoint, {
    method: "POST",
    headers,
    body: params.toString(),
    signal: requestSignal(options.signal, options.timeoutMs),
  });

  if (!response.ok) {
    let errorBody: Record<string, unknown> | null = null;
    try {
      const json = await response.json() as unknown;
      if (json && typeof json === "object" && !Array.isArray(json)) {
        errorBody = json as Record<string, unknown>;
      }
    } catch {
      // non-JSON error body — fall through to generic error
    }
    if (errorBody && typeof errorBody.error === "string") {
      const description = typeof errorBody.error_description === "string"
        ? errorBody.error_description
        : errorBody.error;
      const errorUri = typeof errorBody.error_uri === "string" ? errorBody.error_uri : undefined;
      throw new OAuthError(errorBody.error, description, errorUri);
    }
    throw new OAuthError(
      "invalid_response",
      `Authorization code exchange failed (HTTP ${response.status})`,
    );
  }

  const json = await response.json() as unknown;
  if (!json || typeof json !== "object" || Array.isArray(json)) {
    throw new OAuthError("invalid_response", "Token endpoint response is not a valid JSON object");
  }
  return deserializeTokenResponse(json as Record<string, unknown>);
}
