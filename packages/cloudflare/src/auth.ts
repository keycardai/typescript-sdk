import { JWKSOAuthKeyring } from "@keycardai/oauth/keyring";
import { JWTVerifier } from "@keycardai/oauth/jwt/verifier";
import {
  BadRequestError,
  UnauthorizedError,
  InvalidTokenError,
  InsufficientScopeError,
  HTTPError,
  OAuthError,
  JWKSError,
  JWKSKeyNotFoundError,
} from "@keycardai/oauth/errors";
import type { AuthInfo, BearerAuthOptions } from "./types.js";

// Module-level shared keyring. The keyring caches JWKS responses per
// (issuer, kid) with a TTL, which is the only cache that meaningfully
// affects request latency. Each `verifyBearerToken` call constructs a
// fresh `JWTVerifier` around this keyring; that construction is a handful
// of Set literals and is sub-millisecond.
const sharedKeyring = new JWKSOAuthKeyring();

/**
 * Constructs the OAuth Protected Resource Metadata URL for WWW-Authenticate headers.
 */
function getResourceMetadataUrl(requestUrl: URL): string {
  return `${requestUrl.origin}/.well-known/oauth-protected-resource`;
}

/**
 * Verifies a Bearer token from a Workers request.
 *
 * Returns `AuthInfo` on success, or a `Response` (400/401/403) on failure.
 * This is the Workers equivalent of `requireBearerAuth` Express middleware.
 */
export async function verifyBearerToken(
  request: Request,
  options: BearerAuthOptions,
): Promise<AuthInfo | Response> {
  const url = new URL(request.url);
  const resourceMetadataUrl = getResourceMetadataUrl(url);

  // Catch the common deployment footgun where `KEYCARD_ISSUER` is unset in
  // the Worker's env bindings and flows through as `undefined` despite the
  // type claiming `string`. Fail the request with a clear message instead of
  // crashing inside the verifier construction path.
  const hasIssuers =
    typeof options.issuers === "string"
      ? options.issuers.length > 0
      : Array.isArray(options.issuers) && options.issuers.length > 0;
  if (!hasIssuers) {
    throw new Error(
      "verifyBearerToken: `issuers` is required. When using `createKeycardWorker`, " +
        "ensure the `KEYCARD_ISSUER` env binding is set.",
    );
  }

  try {
    const credentials = request.headers.get("Authorization");
    if (!credentials) {
      throw new UnauthorizedError("No credentials");
    }

    const [scheme, token] = credentials.split(" ");
    if (!token) {
      throw new BadRequestError("Malformed credentials");
    }
    if (scheme.toLowerCase() !== "bearer") {
      throw new InvalidTokenError("Unsupported authentication scheme");
    }

    const verifier = new JWTVerifier(sharedKeyring, {
      issuers: options.issuers,
      audiences: options.audiences,
    });
    const claims = await verifier.verify(token);

    const authInfo: AuthInfo = {
      token,
      clientId: typeof claims.client_id === "string" ? claims.client_id : "",
      scopes: typeof claims.scope === "string" ? claims.scope.split(" ").filter(Boolean) : [],
      subject: typeof claims.sub === "string" ? claims.sub : undefined,
      subProfile: typeof claims.sub_profile === "string" ? claims.sub_profile : undefined,
      keycardAppId: typeof claims.keycard_app_id === "string" ? claims.keycard_app_id : undefined,
    };

    if (typeof claims.aud === "string") {
      try {
        authInfo.resource = new URL(claims.aud);
      } catch {
        // aud is not a URL — skip
      }
    }

    if (typeof claims.exp === "number") {
      authInfo.expiresAt = claims.exp;
    }

    // Check resource audience — compare against origin only, since tokens
    // are scoped to a resource server, not a specific path or query string.
    if (authInfo.resource && authInfo.resource.origin !== url.origin) {
      throw new InvalidTokenError("Token not intended for resource");
    }

    // Check required scopes
    const { requiredScopes = [] } = options;
    if (requiredScopes.length > 0) {
      const hasAllScopes = requiredScopes.every((scope) =>
        authInfo.scopes.includes(scope),
      );
      if (!hasAllScopes) {
        throw new InsufficientScopeError("Insufficient scope");
      }
    }

    // Check expiration
    if (authInfo.expiresAt && authInfo.expiresAt < Date.now() / 1000) {
      throw new InvalidTokenError("Token has expired");
    }

    return authInfo;
  } catch (error) {
    if (error instanceof BadRequestError) {
      return new Response(null, { status: 400 });
    }

    if (error instanceof UnauthorizedError) {
      return new Response(null, {
        status: 401,
        headers: {
          "WWW-Authenticate": `Bearer resource_metadata="${resourceMetadataUrl}"`,
        },
      });
    }

    if (error instanceof InsufficientScopeError) {
      return new Response(null, {
        status: 403,
        headers: {
          "WWW-Authenticate": `Bearer error="${error.errorCode}", error_description="${error.message}", resource_metadata="${resourceMetadataUrl}"`,
        },
      });
    }

    if (error instanceof InvalidTokenError) {
      return new Response(null, {
        status: 401,
        headers: {
          "WWW-Authenticate": `Bearer error="${error.errorCode}", error_description="${error.message}", resource_metadata="${resourceMetadataUrl}"`,
        },
      });
    }

    if (error instanceof JWKSKeyNotFoundError) {
      // A forged token, or a valid token whose signing key rotated out of the
      // JWKS: the resource server cannot validate it. RFC 6750 invalid_token
      // so the client re-runs authorization rather than seeing a server error.
      return new Response(null, {
        status: 401,
        headers: {
          "WWW-Authenticate": `Bearer error="invalid_token", error_description="Unable to verify token signing key", resource_metadata="${resourceMetadataUrl}"`,
        },
      });
    }

    if (error instanceof JWKSError || error instanceof HTTPError || error instanceof OAuthError) {
      // JWKS fetch, discovery, or metadata failed: verification could not
      // complete for a server-side reason (unreachable zone, non-2xx JWKS,
      // malformed AS metadata). Signal a retryable 503 with a small body,
      // no internals, and no WWW-Authenticate challenge — this is not an
      // auth failure, so the client should not re-run authorization.
      //
      // The HTTPError/OAuthError bases here are the discovery/metadata
      // failures thrown raw by the keyring's discovery path. Token-level
      // subclasses (BadRequest/Unauthorized, InvalidToken/InsufficientScope)
      // are matched in the branches above, so any new client-facing
      // OAuthError/HTTPError must be handled before this branch or it will
      // be mis-bucketed as 503.
      return new Response(JSON.stringify({ error: "temporarily_unavailable" }), {
        status: 503,
        headers: { "Content-Type": "application/json" },
      });
    }

    // Genuinely unexpected error. Rethrow so it surfaces through the
    // Worker's own error handling instead of masquerading as an auth
    // failure. All expected verification failures are mapped above.
    throw error;
  }
}

/**
 * Type guard: returns true if the result is an error Response (not AuthInfo).
 */
export function isAuthError(result: AuthInfo | Response): result is Response {
  return result instanceof Response;
}
