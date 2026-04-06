import { JWKSOAuthKeyring } from "@keycardai/oauth/keyring";
import { JWTVerifier } from "@keycardai/oauth/jwt/verifier";
import {
  BadRequestError,
  UnauthorizedError,
  InvalidTokenError,
  InsufficientScopeError,
} from "@keycardai/oauth/errors";
import type { AuthInfo, BearerAuthOptions } from "./types.js";

// Module-level keyring is safe: it only caches public JWKS keys, not user tokens.
let sharedVerifier: JWTVerifier | undefined;

function getVerifier(): JWTVerifier {
  if (!sharedVerifier) {
    const keyring = new JWKSOAuthKeyring();
    sharedVerifier = new JWTVerifier(keyring);
  }
  return sharedVerifier;
}

/** @internal Reset shared verifier (for testing). */
export function _resetVerifier(): void {
  sharedVerifier = undefined;
}

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
  options: BearerAuthOptions = {},
): Promise<AuthInfo | Response> {
  const url = new URL(request.url);
  const resourceMetadataUrl = getResourceMetadataUrl(url);

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

    const verifier = getVerifier();
    const claims = await verifier.verify(token);

    const authInfo: AuthInfo = {
      token,
      clientId: typeof claims.client_id === "string" ? claims.client_id : "",
      scopes: typeof claims.scope === "string" ? claims.scope.split(" ").filter(Boolean) : [],
      subject: typeof claims.sub === "string" ? claims.sub : undefined,
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

    // Unexpected error — return 401
    return new Response(null, {
      status: 401,
      headers: {
        "WWW-Authenticate": `Bearer resource_metadata="${resourceMetadataUrl}"`,
      },
    });
  }
}

/**
 * Type guard: returns true if the result is an error Response (not AuthInfo).
 */
export function isAuthError(result: AuthInfo | Response): result is Response {
  return result instanceof Response;
}
