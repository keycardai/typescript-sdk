import { fetchAuthorizationServerMetadata } from "./discovery.js";

// =============================================================================
// Token Exchange Types (RFC 8693)
// =============================================================================

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
  #tokenEndpoint?: string;
  #discoveryPromise?: Promise<string>;

  constructor(issuerUrl: string, options?: TokenExchangeClientOptions) {
    this.#issuerUrl = issuerUrl;
    this.#clientId = options?.clientId;
    this.#clientSecret = options?.clientSecret;
  }

  async exchangeToken(request: TokenExchangeRequest): Promise<TokenResponse> {
    const tokenEndpoint = await this.#getTokenEndpoint();
    const body = serializeRequest(request);

    const headers: Record<string, string> = {
      "Content-Type": "application/x-www-form-urlencoded",
    };

    if (this.#clientId && this.#clientSecret) {
      const credentials = btoa(`${this.#clientId}:${this.#clientSecret}`);
      headers["Authorization"] = `Basic ${credentials}`;
    }

    const response = await fetch(tokenEndpoint, {
      method: "POST",
      headers,
      body: body.toString(),
    });

    if (!response.ok) {
      let errorDetail = "";
      try {
        const errorBody = await response.json() as Record<string, unknown>;
        errorDetail = typeof errorBody.error_description === "string"
          ? errorBody.error_description
          : typeof errorBody.error === "string"
            ? errorBody.error
            : "";
      } catch {
        // ignore parse errors
      }
      throw new Error(
        `Token exchange failed (HTTP ${response.status})${errorDetail ? `: ${errorDetail}` : ""}`,
      );
    }

    const json = await response.json() as Record<string, unknown>;
    return deserializeResponse(json);
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
