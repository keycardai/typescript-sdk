import type { Request, Response, NextFunction, RequestHandler } from "express";
import { OAuthTokenVerifier } from "@modelcontextprotocol/sdk/server/auth/provider.js"
import { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { JWTOAuthTokenVerifier } from "../verifiers/jwt.js";
import { JWKSOAuthKeyring } from "@keycardai/oauth/keyring";
import { getOAuthProtectedResourceMetadataUrl } from "../router.js"
import { BadRequestError, UnauthorizedError, InvalidTokenError, InsufficientScopeError } from "../errors.js";

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
    if (!issuers) {
      throw new Error(
        "requireBearerAuth: provide either `verifier` or `issuers` — " +
          "passing neither would accept any signed JWT",
      );
    }
    const keyring = new JWKSOAuthKeyring();
    verifier = new JWTOAuthTokenVerifier(keyring, { issuers, audiences });
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

      if (!!authInfo.resource && authInfo.resource.toString() !== url) {
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
      } else {
        next(error);
      }
    }
  }
}
