import { basicAuthorization } from "./basicAuthorization.js";
import { requireClientAuthentication, type ApplicationCredential } from "./credentials.js";
import { assertMetadataIssuer, fetchAuthorizationServerMetadata, type OAuthAuthorizationServerMetadata } from "./discovery.js";
import { ConfigurationError, HTTPError, OAuthError, TokenRevocationHTTPError } from "./errors.js";
import { requestSignal } from "./requestSignal.js";
import { discardResponseBody, readResponseText } from "./responseBody.js";
import { parseOAuthError } from "./tokenEndpointError.js";

export interface RevokeTokenOptions {
  clientId?: string;
  clientSecret?: string;
  credential?: ApplicationCredential;
  /** Default: "refresh_token". */
  tokenTypeHint?: string;
  /** Pre-discovered metadata. When supplied, no discovery request is made. */
  metadata?: OAuthAuthorizationServerMetadata;
  /** HTTP transport for discovery and revocation. Defaults to global fetch. */
  fetch?: typeof globalThis.fetch;
  signal?: AbortSignal;
  /** Timeout in milliseconds per request (default 10 seconds; 0 disables). */
  timeoutMs?: number;
}

/**
 * Revoke a token at the advertised RFC 7009 endpoint. HTTP 200 is success
 * without a response body, including when the server does not recognize the token.
 */
export async function revokeToken(
  issuer: string | undefined,
  token: string,
  options: RevokeTokenOptions,
): Promise<void> {
  if (typeof token !== "string" || token.length === 0) {
    throw new ConfigurationError("revokeToken requires a token");
  }
  const { clientId, clientSecret, credential, metadata } = options;
  if (credential !== undefined && (clientId !== undefined || clientSecret !== undefined)) {
    throw new ConfigurationError("revokeToken: provide either credential or clientId and optional clientSecret");
  }
  const authenticator = credential === undefined
    ? undefined
    : requireClientAuthentication(credential, "revokeToken");
  if (!authenticator && (typeof clientId !== "string" || !clientId ||
    (clientSecret !== undefined && (typeof clientSecret !== "string" || !clientSecret)))) {
    throw new ConfigurationError("revokeToken requires a clientId and, if supplied, a nonempty clientSecret");
  }

  const zoneIssuer = issuer ?? metadata?.issuer;
  if (!isUrlWithProtocol(zoneIssuer, "http:", "https:")) {
    throw new ConfigurationError("revokeToken requires an HTTP or HTTPS issuer URL");
  }
  if (metadata) assertMetadataIssuer(zoneIssuer, metadata, "revokeToken");
  const transport = options.fetch ?? globalThis.fetch;
  const server = metadata ?? await withTransport("Revocation discovery", options, (signal) =>
    fetchAuthorizationServerMetadata(zoneIssuer, { signal, timeoutMs: 0, fetch: transport }),
  );
  const endpoint = server.revocation_endpoint;
  if (!isUrlWithProtocol(endpoint, "https:")) {
    throw new ConfigurationError("revokeToken requires an HTTPS revocation_endpoint in authorization server metadata");
  }

  options.signal?.throwIfAborted();
  const params = new URLSearchParams({
    token,
    token_type_hint: options.tokenTypeHint ?? "refresh_token",
  });
  const headers: Record<string, string> = { "Content-Type": "application/x-www-form-urlencoded" };
  if (authenticator) {
    // The zone issuer is the audience for a revocation client assertion.
    const auth = await authenticator.clientAuthentication(zoneIssuer, zoneIssuer);
    Object.assign(headers, auth.headers);
    for (const [name, value] of Object.entries(auth.form)) params.set(name, value);
  } else if (clientSecret !== undefined) {
    headers.Authorization = basicAuthorization(clientId!, clientSecret);
  } else {
    params.set("client_id", clientId!);
  }

  await withTransport("Token revocation", options, async (signal) => {
    const response = await transport(endpoint, {
      method: "POST",
      headers,
      body: params.toString(),
      signal,
      redirect: "manual",
    });
    if (response.status === 200) {
      discardResponseBody(response);
      return;
    }
    const error = parseOAuthError(await readResponseText(response), response.status);
    throw error ?? new HTTPError(
      `Token revocation failed (HTTP ${response.status})`,
      response.status,
      undefined,
      response.headers?.get("Retry-After") ?? undefined,
    );
  });
}

function isUrlWithProtocol(value: string | undefined, ...protocols: string[]): value is string {
  if (!value) return false;
  try {
    const { protocol } = new URL(value);
    return protocols.includes(protocol);
  } catch {
    return false;
  }
}

async function withTransport<T>(
  operation: string,
  options: RevokeTokenOptions,
  request: (signal: AbortSignal | undefined) => Promise<T>,
): Promise<T> {
  const signal = requestSignal(options.signal, options.timeoutMs);
  signal?.throwIfAborted();
  try {
    return await request(signal);
  } catch (cause) {
    signal?.throwIfAborted();
    if (cause instanceof OAuthError) throw cause;
    if (cause instanceof HTTPError) {
      throw new TokenRevocationHTTPError(cause.message, cause.status, cause.cause, cause.retryAfter);
    }
    throw new TokenRevocationHTTPError(`${operation} request failed`, undefined, cause);
  }
}
