import { ConfigurationError, HTTPError, OAuthError, ResponseBodyTooLargeError } from "./errors.js";
import { readResponseText } from "./responseBody.js";
import { tokenEndpointError } from "./tokenEndpointError.js";
import type { ApplicationCredential } from "./credentials.js";
import { basicAuthorization } from "./basicAuthorization.js";
import { buildSubstituteUserToken } from "./jwt/substituteUser.js";
import { DEFAULT_FETCH_TIMEOUT_MS, TokenEndpointResolver, type TokenEndpointCacheOptions } from "./tokenEndpoint.js";
import {
  fetchIdentityToken,
  validateIdentityTokenSource,
  type IdentityTokenFetcher,
  type IdentityTokenSource,
} from "./identityTokenSource.js";

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
   * the client_id form parameter beside `clientAssertion`, such as a v2 token
   * credential's public ID. A request ID with HTTP Basic is a configuration error.
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
   * static `clientId`/`clientSecret`. A shared-secret credential sets the
   * per-request Authorization header from its `getAuth(issuer)`. When
   * `getAuth(issuer)` returns null and the request carries no
   * `clientAssertion`, `exchangeToken` takes `clientAssertion`,
   * `clientAssertionType` and `clientId` from the credential's
   * `prepareTokenExchangeRequest`, so an assertion-based credential such as
   * `WorkloadIdentity` or `WebIdentity` authenticates every exchange. The
   * request's other fields are sent as the caller set them.
   */
  credential?: ApplicationCredential;
  /**
   * Supplies a fresh actor JWT for each exchange, unless the request sets
   * its own actor token. The source is not called for impersonation.
   */
  actor?: IdentityTokenSource | IdentityTokenFetcher;
  /**
   * Timeout for each request to the authorization server: token endpoint
   * discovery and the token request itself. Default: 10 seconds.
   */
  fetchTimeoutMs?: number;
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
  #actor?: IdentityTokenSource | IdentityTokenFetcher;
  #tokenEndpoint: TokenEndpointResolver;
  #fetchTimeoutMs: number;

  constructor(issuer: string, options?: TokenExchangeClientOptions) {
    this.#issuer = issuer;
    this.#clientId = options?.clientId;
    this.#clientSecret = options?.clientSecret;
    this.#credential = options?.credential;
    const actor = options?.actor;
    if (actor !== undefined) {
      validateIdentityTokenSource(actor);
    }
    this.#actor = actor;
    this.#fetchTimeoutMs = options?.fetchTimeoutMs ?? DEFAULT_FETCH_TIMEOUT_MS;
    this.#tokenEndpoint = new TokenEndpointResolver(issuer, options);
  }

  async exchangeToken(
    request: TokenExchangeRequest,
    options?: ExchangeOptions,
  ): Promise<TokenResponse> {
    const issuer = options?.issuer ?? this.#issuer;
    const basicAuth = request.clientAssertion ? null : this.#resolveBasicAuth(issuer);
    if (basicAuth && request.clientId) {
      throw new ConfigurationError("Token exchange clientId cannot be sent with HTTP Basic");
    }

    if (this.#actor && !request.actorToken && request.subjectTokenType !== TokenType.SUBSTITUTE_USER) {
      request = {
        ...request,
        actorToken: await fetchIdentityToken(this.#actor),
        actorTokenType: "urn:ietf:params:oauth:token-type:jwt",
      };
    }

    const tokenEndpoint = await this.#tokenEndpoint.resolve();

    const headers: Record<string, string> = {
      "Content-Type": "application/x-www-form-urlencoded",
    };

    if (basicAuth) {
      headers["Authorization"] = basicAuthorization(basicAuth.clientId, basicAuth.clientSecret);
    }

    const body = serializeRequest(
      basicAuth || request.clientAssertion
        ? request
        : await this.#withCredentialAssertion(request, tokenEndpoint, issuer),
    );

    const signal = AbortSignal.timeout(this.#fetchTimeoutMs);
    let response: Response;
    let bodyText: string;
    try {
      response = await fetch(tokenEndpoint, {
        method: "POST",
        headers,
        body: body.toString(),
        signal,
      });
      bodyText = await readResponseText(response);
    } catch (cause) {
      if (cause instanceof ResponseBodyTooLargeError) {
        throw cause;
      }
      // Some fetch implementations reject an aborted body read with a separate AbortError.
      if (signal.aborted && (cause === signal.reason || (cause instanceof DOMException && cause.name === "AbortError"))) {
        throw signal.reason;
      }
      throw new HTTPError(cause instanceof Error ? cause.message : String(cause), undefined, cause);
    }

    if (!response.ok) {
      throw await tokenEndpointError(response, "Token exchange", bodyText);
    }

    let json: unknown;
    try {
      json = JSON.parse(bodyText);
    } catch {
      throw new OAuthError("invalid_response", "Token exchange response is not valid JSON");
    }
    if (!json || typeof json !== "object" || Array.isArray(json)) {
      throw new OAuthError("invalid_response", "Token exchange response is not a valid JSON object");
    }
    return deserializeTokenResponse(json as Record<string, unknown>);
  }

  async impersonate(req: ImpersonateRequest): Promise<TokenResponse> {
    if (!req.userIdentifier) {
      throw new Error("impersonate: userIdentifier is required");
    }
    if (!req.resource) {
      throw new Error("impersonate: resource is required");
    }
    const subjectToken = buildSubstituteUserToken(req.userIdentifier);
    let request: TokenExchangeRequest = { subjectToken, resource: req.resource };
    if (this.#credential) {
      const tokenEndpoint = await this.#tokenEndpoint.resolve();
      const prepared = await this.#credential.prepareTokenExchangeRequest(
        subjectToken,
        req.resource,
        { tokenEndpoint, issuer: req.issuer },
      );
      request = { ...prepared, subjectToken, resource: req.resource };
    }
    return this.exchangeToken(
      {
        ...request,
        subjectTokenType: TokenType.SUBSTITUTE_USER,
        scope: req.scope,
        actorToken: undefined,
        actorTokenType: undefined,
      },
      { issuer: req.issuer },
    );
  }

  /**
   * Adds the credential's client assertion to `request`. Only the
   * client-authentication fields come from the credential. Returns
   * `request` unchanged when there is no
   * credential or the credential produces no assertion.
   */
  async #withCredentialAssertion(
    request: TokenExchangeRequest,
    tokenEndpoint: string,
    issuer: string,
  ): Promise<TokenExchangeRequest> {
    if (!this.#credential) {
      return request;
    }
    const prepared = await this.#credential.prepareTokenExchangeRequest(
      request.subjectToken,
      request.resource ?? "",
      { tokenEndpoint, issuer },
    );
    if (!prepared.clientAssertion) {
      return request;
    }
    return {
      ...request,
      clientAssertion: prepared.clientAssertion,
      clientAssertionType: prepared.clientAssertionType,
      clientId: prepared.clientId,
    };
  }

  #resolveBasicAuth(
    issuer: string,
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
