import { fetchAuthorizationServerMetadata } from "./discovery.js";
import { OAuthError } from "./errors.js";

/**
 * RFC 7591 Dynamic Client Registration request metadata.
 * Reference: https://datatracker.ietf.org/doc/html/rfc7591#section-2
 */
export interface ClientRegistrationRequest {
  clientName?: string;
  clientUri?: string;
  logoUri?: string;
  tosUri?: string;
  policyUri?: string;
  softwareId?: string;
  softwareVersion?: string;
  jwksUri?: string;
  jwks?: Record<string, unknown>;
  tokenEndpointAuthMethod?: string;
  redirectUris?: readonly string[];
  grantTypes?: readonly string[];
  responseTypes?: readonly string[];
  scope?: string;
  /**
   * Vendor-extension or AS-specific fields not covered by the typed shape.
   * Merged into the request body verbatim (snake_case keys preserved).
   */
  additionalMetadata?: Record<string, unknown>;
}

/**
 * RFC 7591 Dynamic Client Registration response.
 * Reference: https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.1
 */
export interface ClientRegistrationResponse {
  clientId: string;
  clientSecret?: string;
  clientIdIssuedAt?: number;
  clientSecretExpiresAt?: number;
  clientName?: string;
  clientUri?: string;
  logoUri?: string;
  tosUri?: string;
  policyUri?: string;
  softwareId?: string;
  softwareVersion?: string;
  jwksUri?: string;
  jwks?: Record<string, unknown>;
  tokenEndpointAuthMethod?: string;
  redirectUris?: string[];
  grantTypes?: string[];
  responseTypes?: string[];
  scope?: string[];
  registrationAccessToken?: string;
  registrationClientUri?: string;
  /**
   * The full unparsed response body. Useful for AS-specific extensions
   * not captured by the typed fields above.
   */
  raw: Record<string, unknown>;
}

export interface RegisterClientOptions {
  signal?: AbortSignal;
  /** Request timeout in milliseconds. Ignored if `signal` is already provided. */
  timeoutMs?: number;
}

/**
 * Register a new OAuth 2.0 client with an authorization server (RFC 7591).
 *
 * Discovers `registration_endpoint` from the AS's
 * `.well-known/oauth-authorization-server` metadata, POSTs the registration
 * request as JSON, and returns the issued client credentials.
 *
 * Throws:
 * - `Error` when the AS does not advertise `registration_endpoint`.
 * - `OAuthError` when the AS returns an RFC 6749 §5.2 error response.
 * - `Error` on non-OAuth HTTP failures or malformed responses.
 */
export async function registerClient(
  issuerUrl: string,
  request: ClientRegistrationRequest,
  options?: RegisterClientOptions,
): Promise<ClientRegistrationResponse> {
  const signal = options?.signal ??
    (options?.timeoutMs != null ? AbortSignal.timeout(options.timeoutMs) : undefined);

  const metadata = await fetchAuthorizationServerMetadata(issuerUrl, { signal });
  if (!metadata.registration_endpoint) {
    throw new Error(
      `Authorization server "${issuerUrl}" does not advertise a registration_endpoint`,
    );
  }

  const response = await fetch(metadata.registration_endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify(serializeRequest(request)),
    signal,
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
    throw new Error(`Client registration failed (HTTP ${response.status})`);
  }

  let json: unknown;
  try {
    json = await response.json();
  } catch {
    throw new Error("Client registration response is not valid JSON");
  }
  if (!json || typeof json !== "object" || Array.isArray(json)) {
    throw new Error("Client registration response is not a valid JSON object");
  }
  const body = json as Record<string, unknown>;

  if (typeof body.client_id !== "string") {
    throw new Error("Client registration response missing client_id");
  }

  return deserializeResponse(body);
}

function serializeRequest(request: ClientRegistrationRequest): Record<string, unknown> {
  // additionalMetadata goes in first so named fields always take precedence
  // over vendor extensions — callers cannot accidentally override client_name etc.
  const body: Record<string, unknown> = {};
  if (request.additionalMetadata) {
    for (const [key, value] of Object.entries(request.additionalMetadata)) {
      body[key] = value;
    }
  }
  if (request.clientName !== undefined) body.client_name = request.clientName;
  if (request.clientUri !== undefined) body.client_uri = request.clientUri;
  if (request.logoUri !== undefined) body.logo_uri = request.logoUri;
  if (request.tosUri !== undefined) body.tos_uri = request.tosUri;
  if (request.policyUri !== undefined) body.policy_uri = request.policyUri;
  if (request.softwareId !== undefined) body.software_id = request.softwareId;
  if (request.softwareVersion !== undefined) body.software_version = request.softwareVersion;
  if (request.jwksUri !== undefined) body.jwks_uri = request.jwksUri;
  if (request.jwks !== undefined) body.jwks = request.jwks;
  if (request.tokenEndpointAuthMethod !== undefined) {
    body.token_endpoint_auth_method = request.tokenEndpointAuthMethod;
  }
  if (request.redirectUris !== undefined) body.redirect_uris = [...request.redirectUris];
  if (request.grantTypes !== undefined) body.grant_types = [...request.grantTypes];
  if (request.responseTypes !== undefined) body.response_types = [...request.responseTypes];
  if (request.scope !== undefined) body.scope = request.scope;
  return body;
}

function deserializeResponse(body: Record<string, unknown>): ClientRegistrationResponse {
  const response: ClientRegistrationResponse = {
    clientId: body.client_id as string,
    raw: body,
  };
  if (typeof body.client_secret === "string") response.clientSecret = body.client_secret;
  if (typeof body.client_id_issued_at === "number") response.clientIdIssuedAt = body.client_id_issued_at;
  if (typeof body.client_secret_expires_at === "number") {
    response.clientSecretExpiresAt = body.client_secret_expires_at;
  }
  if (typeof body.client_name === "string") response.clientName = body.client_name;
  if (typeof body.client_uri === "string") response.clientUri = body.client_uri;
  if (typeof body.logo_uri === "string") response.logoUri = body.logo_uri;
  if (typeof body.tos_uri === "string") response.tosUri = body.tos_uri;
  if (typeof body.policy_uri === "string") response.policyUri = body.policy_uri;
  if (typeof body.software_id === "string") response.softwareId = body.software_id;
  if (typeof body.software_version === "string") response.softwareVersion = body.software_version;
  if (typeof body.jwks_uri === "string") response.jwksUri = body.jwks_uri;
  if (body.jwks && typeof body.jwks === "object") {
    response.jwks = body.jwks as Record<string, unknown>;
  }
  if (typeof body.token_endpoint_auth_method === "string") {
    response.tokenEndpointAuthMethod = body.token_endpoint_auth_method;
  }
  response.redirectUris = normalizeStringArray(body.redirect_uris);
  response.grantTypes = normalizeStringArray(body.grant_types);
  response.responseTypes = normalizeStringArray(body.response_types);
  response.scope = normalizeScope(body.scope);
  if (typeof body.registration_access_token === "string") {
    response.registrationAccessToken = body.registration_access_token;
  }
  if (typeof body.registration_client_uri === "string") {
    response.registrationClientUri = body.registration_client_uri;
  }
  return response;
}

function normalizeStringArray(value: unknown): string[] | undefined {
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) {
    const out = value.filter((v): v is string => typeof v === "string");
    return out.length > 0 ? out : undefined;
  }
  return undefined;
}

function normalizeScope(value: unknown): string[] | undefined {
  if (typeof value === "string") {
    const parts = value.split(" ").filter(Boolean);
    return parts.length > 0 ? parts : undefined;
  }
  return normalizeStringArray(value);
}

