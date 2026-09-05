import { OAuthError } from "./errors.js";
import type { ApplicationCredential } from "./credentials.js";
import { buildSubstituteUserToken } from "./jwt/substituteUser.js";
import { TokenEndpointResolver, type TokenEndpointCacheOptions } from "./tokenEndpoint.js";

// =============================================================================
// Token Exchange Types (RFC 8693)
// =============================================================================

export const TokenType = {
  ACCESS_TOKEN: "urn:ietf:params:oauth:token-type:access_token",
  /**
   * Vendor URN for substitute-user (impersonation) subject tokens.
   * Recognized by the Keycard authorization server; not registered with IANA.
   */
  SUBSTITUTE_USER: "urn:keycard:params:oauth:token-type:substitute-user",
} as const;
export type TokenType = (typeof TokenType)[keyof typeof TokenType];

export interface TokenExchangeRequest {
  grantType?: string;
  resource?: string;
  audience?: string;
  scope?: string;
  requestedTokenType?: string;
  subjectToken: string;
  subjectTokenType?: string;
  actorToken?: string;
  actorTokenType?: string;
  clientAssertion?: string;
  clientAssertionType?: string;
  /**
   * Names the application credential the client authenticates as, sent as
   * the client_id form parameter. Used with assertion-based credentials that
   * are resolved by ID rather than by the assertion's subject.
   */
  clientId?: string;
}

export interface TokenResponse {
  accessToken: string;
  tokenType: string;
  expiresIn?: number;
  refreshToken?: string;
  scope?: string[];
  issuedTokenType?: string;
  /** OIDC ID token, present when the request includes the appropriate scopes. */
  idToken?: string;
}

export interface TokenExchangeClientOptions extends TokenEndpointCacheOptions {
  clientId?: string;
  clientSecret?: string;
  /**
   * Application credential provider. When set, takes precedence over
   * static `clientId`/`clientSecret` and resolves the per-request
   * Authorization header from the credential's `getAuth(issuer)`.
   */
  credential?: ApplicationCredential;
}

export interface ExchangeOptions {
  /** Zone issuer URL used to select per-zone credentials. */
  issuer?: string;
}

export interface ImpersonateRequest {
  userIdentifier: string;
  resource: string;
  scope?: string;
  /** Zone issuer URL used to select per-zone credentials. */
  issuer?: string;
}

// =============================================================================
// Wire format helpers (camelCase <-> snake_case at the boundary)
// =============================================================================

function serializeRequest(request: TokenExchangeRequest): URLSearchParams {
  const params = new URLSearchParams();

  params.set("grant_type", request.grantType ?? "urn:ietf:params:oauth:grant-type:token-exchange");
  params.set("subject_token", request.subjectToken);
  params.set("subject_token_type", request.subjectTokenType ?? "urn:ietf:params:oauth:token-type:access_token");

  if (request.resource) params.set("resource", request.resource);
  if (request.audience) params.set("audience", request.audience);
  if (request.scope) params.set("scope", request.scope);
  if (request.requestedTokenType) params.set("requested_token_type", request.requestedTokenType);
  if (request.actorToken) params.set("actor_token", request.actorToken);
  if (request.actorTokenType) params.set("actor_token_type", request.actorTokenType);
  if (request.clientAssertion) params.set("client_assertion", request.clientAssertion);
  if (request.clientAssertionType) params.set("client_assertion_type", request.clientAssertionType);
  if (request.clientId) params.set("client_id", request.clientId);

  return params;
}

export function deserializeTokenResponse(json: Record<string, unknown>): TokenResponse {
  const accessToken = json.access_token;
  if (typeof accessToken !== "string" || !accessToken) {
    throw new OAuthError("invalid_response", "Token response missing access_token");
  }

  const response: TokenResponse = {
    accessToken,
    // RFC 6750 names the scheme "Bearer"; used when the server omits token_type.
    tokenType: typeof json.token_type === "string" ? json.token_type : "Bearer",
  };

  if (typeof json.expires_in === "number") response.expiresIn = json.expires_in;
  if (typeof json.refresh_token === "string") response.refreshToken = json.refresh_token;
  if (typeof json.issued_token_type === "string") response.issuedTokenType = json.issued_token_type;
  if (typeof json.id_token === "string") response.idToken = json.id_token;
  if (typeof json.scope === "string") {
    response.scope = json.scope.split(" ").filter(Boolean);
  }

  return response;
}

// =============================================================================
// Token Exchange Client
// =============================================================================

export class TokenExchangeClient {
  #issuer: string;
  #clientId?: string;
  #clientSecret?: string;
  #credential?: ApplicationCredential;
  #tokenEndpoint: TokenEndpointResolver;

  constructor(issuer: string, options?: TokenExchangeClientOptions) {
    this.#issuer = issuer;
    this.#clientId = options?.clientId;
    this.#clientSecret = options?.clientSecret;
    this.#credential = options?.credential;
    this.#tokenEndpoint = new TokenEndpointResolver(issuer, options);
  }

  async exchangeToken(
    request: TokenExchangeRequest,
    options?: ExchangeOptions,
  ): Promise<TokenResponse> {
    const tokenEndpoint = await this.#tokenEndpoint.resolve();
    const body = serializeRequest(request);

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
        // non-JSON or no "error" key — fall through
      }
      throw new OAuthError(
        "invalid_response",
        `Token exchange failed (HTTP ${response.status})`,
      );
    }

    const json = await response.json() as Record<string, unknown>;
    return deserializeTokenResponse(json);
  }

  async impersonate(req: ImpersonateRequest): Promise<TokenResponse> {
    if (!req.userIdentifier) {
      throw new Error("impersonate: userIdentifier is required");
    }
    if (!req.resource) {
      throw new Error("impersonate: resource is required");
    }
    const subjectToken = buildSubstituteUserToken(req.userIdentifier);
    return this.exchangeToken(
      {
        subjectToken,
        subjectTokenType: TokenType.SUBSTITUTE_USER,
        resource: req.resource,
        scope: req.scope,
      },
      { issuer: req.issuer },
    );
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
   * assertion whose `aud` is the token endpoint before invoking {@link exchangeToken}.
   * Throws {@link TokenEndpointDiscoveryError} when discovery fails.
   */
  async getTokenEndpoint(): Promise<string> {
    return this.#tokenEndpoint.resolve();
  }
}
