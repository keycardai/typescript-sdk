import { fetchAuthorizationServerMetadata } from "./discovery.js";
import { OAuthError } from "./errors.js";
import type { ApplicationCredential } from "./credentials.js";
import { buildSubstituteUserToken } from "./jwt/substituteUser.js";

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
}

export interface TokenResponse {
  accessToken: string;
  tokenType: string;
  expiresIn?: number;
  refreshToken?: string;
  scope?: string[];
  issuedTokenType?: string;
}

export interface TokenExchangeClientOptions {
  clientId?: string;
  clientSecret?: string;
  /**
   * Application credential provider. When set, takes precedence over
   * static `clientId`/`clientSecret` and resolves the per-request
   * Authorization header from the credential's `getAuth(zoneId)`.
   */
  credential?: ApplicationCredential;
}

export interface ExchangeOptions {
  zoneId?: string;
}

export interface ImpersonateRequest {
  userIdentifier: string;
  resource: string;
  scope?: string;
  zoneId?: string;
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

  return params;
}

function deserializeResponse(json: Record<string, unknown>): TokenResponse {
  const accessToken = json.access_token;
  if (typeof accessToken !== "string" || !accessToken) {
    throw new Error("Token exchange response missing access_token");
  }

  const response: TokenResponse = {
    accessToken,
    tokenType: typeof json.token_type === "string" ? json.token_type : "bearer",
  };

  if (typeof json.expires_in === "number") response.expiresIn = json.expires_in;
  if (typeof json.refresh_token === "string") response.refreshToken = json.refresh_token;
  if (typeof json.issued_token_type === "string") response.issuedTokenType = json.issued_token_type;
  if (typeof json.scope === "string") {
    response.scope = json.scope.split(" ").filter(Boolean);
  }

  return response;
}

// =============================================================================
// Token Exchange Client
// =============================================================================

export class TokenExchangeClient {
  #issuerUrl: string;
  #clientId?: string;
  #clientSecret?: string;
  #credential?: ApplicationCredential;
  #tokenEndpoint?: string;
  #discoveryPromise?: Promise<string>;

  constructor(issuerUrl: string, options?: TokenExchangeClientOptions) {
    this.#issuerUrl = issuerUrl;
    this.#clientId = options?.clientId;
    this.#clientSecret = options?.clientSecret;
    this.#credential = options?.credential;
  }

  async exchangeToken(
    request: TokenExchangeRequest,
    options?: ExchangeOptions,
  ): Promise<TokenResponse> {
    const tokenEndpoint = await this.#getTokenEndpoint();
    const body = serializeRequest(request);

    const headers: Record<string, string> = {
      "Content-Type": "application/x-www-form-urlencoded",
    };

    const basicAuth = this.#resolveBasicAuth(options?.zoneId);
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
      throw new Error(
        `Token exchange failed (HTTP ${response.status})`,
      );
    }

    const json = await response.json() as Record<string, unknown>;
    return deserializeResponse(json);
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
      { zoneId: req.zoneId },
    );
  }

  #resolveBasicAuth(
    zoneId: string | undefined,
  ): { clientId: string; clientSecret: string } | null {
    if (this.#credential) {
      return this.#credential.getAuth(zoneId);
    }
    if (this.#clientId && this.#clientSecret) {
      return { clientId: this.#clientId, clientSecret: this.#clientSecret };
    }
    return null;
  }

  async #getTokenEndpoint(): Promise<string> {
    if (this.#tokenEndpoint) {
      return this.#tokenEndpoint;
    }

    // Promise-based lock: only one concurrent discovery
    if (!this.#discoveryPromise) {
      this.#discoveryPromise = (async () => {
        const metadata = await fetchAuthorizationServerMetadata(this.#issuerUrl);
        if (!metadata.token_endpoint) {
          throw new Error(`Authorization server "${this.#issuerUrl}" does not advertise a token_endpoint`);
        }
        this.#tokenEndpoint = metadata.token_endpoint;
        return this.#tokenEndpoint;
      })();
    }

    return this.#discoveryPromise;
  }
}
