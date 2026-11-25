import { OAuthError } from "./errors.js";
import { readResponseText } from "./responseBody.js";
import { tokenEndpointError } from "./tokenEndpointError.js";
import type { ApplicationCredential } from "./credentials.js";
import { basicAuthorization } from "./basicAuthorization.js";
import { DEFAULT_FETCH_TIMEOUT_MS, TokenEndpointResolver, type TokenEndpointCacheOptions } from "./tokenEndpoint.js";
import { deserializeTokenResponse, type TokenResponse } from "./tokenExchange.js";

// =============================================================================
// Client Credentials Types (RFC 6749 Section 4.4)
// =============================================================================

export interface ClientCredentialsRequest {
  resource?: string;
  scope?: string;
  clientAssertion?: string;
  clientAssertionType?: string;
  /**
   * Names the application credential the client authenticates as, sent beside
   * a jwt-bearer `clientAssertion`, such as a v2 token credential's public ID.
   * Never sent with HTTP Basic.
   */
  clientId?: string;
}

export interface ClientCredentialsClientOptions extends TokenEndpointCacheOptions {
  clientId?: string;
  clientSecret?: string;
  /**
   * Application credential provider. When set, takes precedence over
   * static `clientId`/`clientSecret` and resolves the per-request
   * Authorization header from the credential's `getAuth(issuer)`.
   */
  credential?: ApplicationCredential;
  /**
   * Timeout for each request to the authorization server: token endpoint
   * discovery and the token request itself. Default: 10 seconds.
   */
  fetchTimeoutMs?: number;
}

export interface RequestTokenOptions {
  /** Zone issuer URL used to select per-zone credentials. */
  issuer?: string;
}

// =============================================================================
// Wire format helpers (camelCase <-> snake_case at the boundary)
// =============================================================================

function serializeRequest(request: ClientCredentialsRequest): URLSearchParams {
  const params = new URLSearchParams();

  params.set("grant_type", "client_credentials");

  if (request.resource) params.set("resource", request.resource);
  if (request.scope) params.set("scope", request.scope);
  if (request.clientAssertion) params.set("client_assertion", request.clientAssertion);
  if (request.clientAssertionType) params.set("client_assertion_type", request.clientAssertionType);
  if (request.clientId) params.set("client_id", request.clientId);

  return params;
}

// =============================================================================
// Client Credentials Client
// =============================================================================

export class ClientCredentialsClient {
  #issuer: string;
  #clientId?: string;
  #clientSecret?: string;
  #credential?: ApplicationCredential;
  #tokenEndpoint: TokenEndpointResolver;
  #fetchTimeoutMs: number;

  constructor(issuer: string, options?: ClientCredentialsClientOptions) {
    this.#issuer = issuer;
    this.#clientId = options?.clientId;
    this.#clientSecret = options?.clientSecret;
    this.#credential = options?.credential;
    this.#fetchTimeoutMs = options?.fetchTimeoutMs ?? DEFAULT_FETCH_TIMEOUT_MS;
    this.#tokenEndpoint = new TokenEndpointResolver(issuer, options);
  }

  async requestToken(
    request?: ClientCredentialsRequest,
    options?: RequestTokenOptions,
  ): Promise<TokenResponse> {
    const tokenEndpoint = await this.#tokenEndpoint.resolve();
    const body = serializeRequest(request ?? {});

    const headers: Record<string, string> = {
      "Content-Type": "application/x-www-form-urlencoded",
    };

    const basicAuth = this.#resolveBasicAuth(options?.issuer);
    if (basicAuth) {
      headers["Authorization"] = basicAuthorization(basicAuth.clientId, basicAuth.clientSecret);
    }

    const response = await fetch(tokenEndpoint, {
      method: "POST",
      headers,
      body: body.toString(),
      signal: AbortSignal.timeout(this.#fetchTimeoutMs),
    });

    if (!response.ok) {
      throw await tokenEndpointError(response, "Client credentials request");
    }

    const text = await readResponseText(response);
    let json: unknown;
    try {
      json = JSON.parse(text);
    } catch {
      throw new OAuthError("invalid_response", "Client credentials response is not valid JSON");
    }
    if (!json || typeof json !== "object" || Array.isArray(json)) {
      throw new OAuthError("invalid_response", "Client credentials response is not a valid JSON object");
    }
    return deserializeTokenResponse(json as Record<string, unknown>);
  }

  #resolveBasicAuth(
    issuer: string | undefined,
  ): { clientId: string; clientSecret: string } | null {
    if (this.#credential) {
      return this.#credential.getAuth(issuer);
    }
    if (this.#clientId && this.#clientSecret) {
      return { clientId: this.#clientId, clientSecret: this.#clientSecret };
    }
    return null;
  }

  /**
   * Resolve the authorization server's token endpoint (discovered from metadata
   * and cached for `discoveryTtlMs`). Exposed so a caller can build a credential
   * assertion whose `aud` is the token endpoint before invoking {@link requestToken}.
   * Throws {@link TokenEndpointDiscoveryError} when discovery fails.
   */
  async getTokenEndpoint(): Promise<string> {
    return this.#tokenEndpoint.resolve();
  }
}
