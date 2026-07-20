import type { Request, Response, NextFunction, RequestHandler } from "express";
import type { AuthInfo, OAuthTokenVerifier } from "../../../shared/auth.js";
import { JWTOAuthTokenVerifier } from "../verifiers/jwt.js";
import { JWKSOAuthKeyring } from "@keycardai/oauth/keyring";
import { getOAuthProtectedResourceMetadataUrl } from "../router.js"
import { BadRequestError, UnauthorizedError, InvalidTokenError, InsufficientScopeError, HTTPError, OAuthError, JWKSError, JWKSKeyNotFoundError } from "../errors.js";

export interface AuthenticatedRequest extends Request {
  auth: AuthInfo;
}

export type BearerAuthMiddlewareOptions = {
  /**
   * Token verifier implementation. If omitted, a `JWTOAuthTokenVerifier` is
   * constructed from `issuers` / `audiences`. Exactly one of `verifier` or
   * `issuers` must be provided.
   */
  verifier?: OAuthTokenVerifier;
  /**
   * Issuer(s) to trust when auto-constructing the default verifier. Tokens
   * whose `iss` doesn't match are rejected before any key lookup.
   */
  issuers?: string | readonly string[];
  /**
   * Audience(s) to enforce when auto-constructing the default verifier. When
   * set, tokens must present an `aud` that contains one of these values.
   */
  audiences?: string | readonly string[];
  requiredScopes?: string[];
};

export function requireBearerAuth({
  verifier,
  issuers,
  audiences,
  requiredScopes = [],
}: BearerAuthMiddlewareOptions): RequestHandler {
  if (!verifier) {
    const configuredIssuers =
      typeof issuers === "string" && issuers.length > 0
        ? issuers
        : Array.isArray(issuers) && issuers.length > 0
          ? issuers
          : undefined;
    if (!configuredIssuers) {
      throw new Error(
        "requireBearerAuth: provide either `verifier` or a non-empty `issuers` — " +
          "passing neither would accept any signed JWT",
      );
    }
    const keyring = new JWKSOAuthKeyring();
    verifier = new JWTOAuthTokenVerifier(keyring, {
      issuers: configuredIssuers,
      audiences,
    });
  }

  return async (req, res, next) => {
    const url = `${req.protocol}://${req.host}${req.originalUrl}`

    try {
      const credentials = req.headers.authorization;
      if (!credentials) {
        throw new UnauthorizedError("No credentials");
      }

      const [scheme, token] = credentials.split(' ');
      if (!token) {
        throw new BadRequestError("Malformed credentials");
      }
      if (scheme.toLowerCase() !== 'bearer') {
        throw new InvalidTokenError("Unsupported authentication scheme");
      }

      const authInfo = await verifier.verifyAccessToken(token);

      if (!!authInfo.resource && new URL(url).origin !== authInfo.resource.origin) {
        throw new InvalidTokenError("Token not intended for resource");
      }

      if (requiredScopes.length > 0) {
        const hasAllScopes = requiredScopes.every(scope =>
          authInfo.scopes.includes(scope)
        );

        if (!hasAllScopes) {
          throw new InsufficientScopeError("Insufficient scope");
        }
      }

      if (!!authInfo.expiresAt && authInfo.expiresAt < Date.now() / 1000) {
        throw new InvalidTokenError("Token has expired");
      }

      (req as Request & { auth?: AuthInfo }).auth = authInfo;
      next();
    } catch (error) {
      let challenge;
      const resourceMetadataUrl = getOAuthProtectedResourceMetadataUrl(new URL(url));

      if (error instanceof BadRequestError) {
        res.status(400).end();
      } else if (error instanceof UnauthorizedError) {
        challenge = `Bearer resource_metadata="${resourceMetadataUrl}"`;
        res.set("WWW-Authenticate", challenge);
        res.status(401).end();
      } else if (error instanceof InvalidTokenError) {
        const challenge = `Bearer error="${error.errorCode}", error_description="${error.message}", resource_metadata="${resourceMetadataUrl}"`;
        res.set("WWW-Authenticate", challenge);
        res.status(401).end();
      } else if (error instanceof InsufficientScopeError) {
        const challenge = `Bearer error="${error.errorCode}", error_description="${error.message}", resource_metadata="${resourceMetadataUrl}"`;
        res.set("WWW-Authenticate", challenge);
        res.status(403).end();
      } else if (error instanceof JWKSKeyNotFoundError) {
        // A forged token, or a valid token whose signing key rotated out of the
        // JWKS: the resource server cannot validate it. RFC 6750 invalid_token
        // so the client re-runs authorization rather than seeing a 500.
        const challenge = `Bearer error="invalid_token", error_description="Unable to verify token signing key", resource_metadata="${resourceMetadataUrl}"`;
        res.set("WWW-Authenticate", challenge);
        res.status(401).end();
      } else if (error instanceof JWKSError || error instanceof HTTPError || error instanceof OAuthError) {
        // JWKS fetch, discovery, or metadata failed: verification could not
        // complete for a server-side reason (unreachable zone, non-2xx JWKS,
        // malformed AS metadata). Signal a retryable 503 with a small body and
        // no internals, rather than a 500 that leaks a stack trace.
        //
        // The HTTPError/OAuthError bases here are the discovery/metadata
        // failures thrown raw by discovery.ts. Token-level subclasses
        // (BadRequest/Unauthorized, InvalidToken/InsufficientScope) are matched
        // in the branches above, so any new client-facing OAuthError/HTTPError
        // must be handled before this branch or it will be mis-bucketed as 503.
        res.status(503).json({ error: "temporarily_unavailable" });
      } else {
        // Genuinely unexpected error. Delegate to the app's error handling
        // (idiomatic Express) instead of swallowing a real bug. All expected
        // verification failures are mapped above, so this no longer catches
        // JWKS/discovery errors.
        next(error);
      }
    }
  }
}
