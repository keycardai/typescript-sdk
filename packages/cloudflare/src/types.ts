// =============================================================================
// Environment Bindings
// =============================================================================

export interface KeycardEnv {
  /** Keycard Zone URL (issuer) for JWKS discovery and metadata. */
  KEYCARD_ISSUER: string;

  // Option A: Client credentials (client_id + client_secret)
  KEYCARD_CLIENT_ID?: string;
  KEYCARD_CLIENT_SECRET?: string;

  // Option B: Web identity (private_key_jwt — no client secret needed)
  KEYCARD_PRIVATE_KEY?: string;

  /** Upstream resource URL for token exchange (e.g. "https://api.github.com"). */
  KEYCARD_RESOURCE_URL?: string;
}

// =============================================================================
// Auth Info (mirrors @modelcontextprotocol/sdk AuthInfo without the dependency)
// =============================================================================

export interface AuthInfo {
  /** The raw bearer token from the request. */
  token: string;
  /** The client_id claim from the JWT. */
  clientId: string;
  /** Scopes granted to this token. */
  scopes: string[];
  /** Token expiration (Unix seconds). */
  expiresAt?: number;
  /** The audience/resource URL the token is intended for. */
  resource?: URL;
  /** JWT subject claim — critical for per-user cache keying in shared isolates. */
  subject?: string;
}

// =============================================================================
// Worker Options
// =============================================================================

export type AuthenticatedFetchHandler<Env extends KeycardEnv = KeycardEnv> = (
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  auth: AuthInfo,
) => Response | Promise<Response>;

export interface KeycardWorkerOptions<Env extends KeycardEnv = KeycardEnv> {
  /** Required scopes for bearer auth verification. */
  requiredScopes?: string[];
  /** Scopes advertised in the protected resource metadata. */
  scopesSupported?: string[];
  /** Human-readable resource name for metadata. */
  resourceName?: string;
  /** Documentation URL for the resource. */
  serviceDocumentationUrl?: string;
  /** The authenticated request handler. Only called after successful auth. */
  fetch: AuthenticatedFetchHandler<Env>;
}

// =============================================================================
// Metadata Options
// =============================================================================

export interface MetadataOptions {
  /** Keycard Zone URL (issuer). */
  issuer: string;
  /** Scopes supported by this resource. */
  scopesSupported?: string[];
  /** Human-readable resource name. */
  resourceName?: string;
  /** Documentation URL. */
  serviceDocumentationUrl?: string;
  /** Public JWKS to serve at /.well-known/jwks.json (for WebIdentity). */
  publicJwks?: { keys: Record<string, unknown>[] };
}

// =============================================================================
// Bearer Auth Options
// =============================================================================

export interface BearerAuthOptions {
  /** Required scopes. Token must have all of these. */
  requiredScopes?: string[];
}
