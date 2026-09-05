import { OAuthError } from "./errors.js";
import type { ApplicationCredential } from "./credentials.js";
import { TokenEndpointResolver, type TokenEndpointCacheOptions } from "./tokenEndpoint.js";
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
   * The client identifier. Accompanies a jwt-bearer `clientAssertion` when the
   * zone resolves the application credential by application ID rather than by
   * the assertion subject. Not needed when the client authenticates at the HTTP
   * layer, such as Basic auth.
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

  constructor(issuer: string, options?: ClientCredentialsClientOptions) {
    this.#issuer = issuer;
    this.#clientId = options?.clientId;
    this.#clientSecret = options?.clientSecret;
    this.#credential = options?.credential;
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
      const credentials = btoa(`${basicAuth.clientId}:${basicAuth.clientSecret}`);
      headers["Authorization"] = `Basic ${credentials}`;
    }

    const response = await fetch(tokenEndpoint, {
      method: "POST",
      headers,
      body: body.toString(),
    });

    if (!response.ok) {
      try {
        const errorBody = await response.json() as Record<string, unknown>;
        if (typeof errorBody.error === "string") {
          const errorCode = errorBody.error;
          const description = typeof errorBody.error_description === "string"
            ? errorBody.error_description
            : errorCode;
          const errorUri = typeof errorBody.error_uri === "string"
            ? errorBody.error_uri
            : undefined;
          throw new OAuthError(errorCode, description, errorUri);
        }
      } catch (e) {
        if (e instanceof OAuthError) throw e;
        // non-JSON or no "error" key: fall through
      }
      throw new OAuthError(
        "invalid_response",
        `Client credentials request failed (HTTP ${response.status})`,
      );
    }

    const json = await response.json() as Record<string, unknown>;
    return deserializeTokenResponse(json);
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
