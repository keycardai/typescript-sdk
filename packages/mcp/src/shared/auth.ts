/**
 * Information about a validated access token, provided to request handlers.
 *
 * Structurally compatible with the official MCP SDK's `AuthInfo`
 * (`@modelcontextprotocol/sdk/server/auth/types.js`): values of either type
 * are interchangeable in both directions via structural typing.
 */
export interface AuthInfo {
  /**
   * The access token.
   */
  token: string;

  /**
   * The client ID associated with this token.
   */
  clientId: string;

  /**
   * Scopes associated with this token.
   */
  scopes: string[];

  /**
   * When the token expires (in seconds since epoch).
   */
  expiresAt?: number;

  /**
   * The RFC 8707 resource server identifier for which this token is valid.
   * If set, this MUST match the MCP server's resource identifier (minus hash fragment).
   */
  resource?: URL;

  /**
   * Additional data associated with the token.
   * This field should be used for any additional data that needs to be attached to the auth info.
   */
  extra?: Record<string, unknown>;
}

/**
 * Verifies bearer access tokens and returns information about them.
 *
 * Structurally compatible with the official MCP SDK's `OAuthTokenVerifier`
 * (`@modelcontextprotocol/sdk/server/auth/provider.js`): implementations of
 * either interface are interchangeable via structural typing.
 */
export interface OAuthTokenVerifier {
  /**
   * Verifies an access token and returns information about it.
   */
  verifyAccessToken(token: string): Promise<AuthInfo>;
}

/**
 * RFC 9728 OAuth Protected Resource Metadata.
 *
 * Structurally compatible with the official MCP SDK's
 * `OAuthProtectedResourceMetadata` (`@modelcontextprotocol/sdk/shared/auth.js`):
 * values of either type are interchangeable in both directions via structural
 * typing. The index signature mirrors the SDK schema's passthrough of
 * unrecognized metadata fields.
 */
export interface OAuthProtectedResourceMetadata {
  resource: string;
  authorization_servers?: string[];
  jwks_uri?: string;
  scopes_supported?: string[];
  bearer_methods_supported?: string[];
  resource_signing_alg_values_supported?: string[];
  resource_name?: string;
  resource_documentation?: string;
  resource_policy_uri?: string;
  resource_tos_uri?: string;
  tls_client_certificate_bound_access_tokens?: boolean;
  authorization_details_types_supported?: string[];
  dpop_signing_alg_values_supported?: string[];
  dpop_bound_access_tokens_required?: boolean;
  [key: string]: unknown;
}

export type InferredOAuthProtectedResourceMetadata = Omit<OAuthProtectedResourceMetadata, "resource">;
