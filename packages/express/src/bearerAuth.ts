import type { Request, Response, NextFunction, RequestHandler } from "express";
import { TokenVerifier } from "@keycardai/oauth/server/tokenVerifier";
import type { TokenVerifierOptions } from "@keycardai/oauth/server/tokenVerifier";
import type { AccessToken } from "@keycardai/oauth/server/accessToken";
import {
  BadRequestError,
  UnauthorizedError,
  InvalidTokenError,
  InsufficientScopeError,
  OAuthError,
} from "@keycardai/oauth/errors";

/**
 * Extends Express `Request` with the verified Keycard `AccessToken`.
 *
 * Cast inside handlers that run after `requireBearerAuth()`:
 * ```ts
 * app.get("/data", (req, res) => {
 *   const { auth } = req as AuthenticatedRequest;
 * });
 * ```
 *
 * Alternatively, adopt Express module augmentation so `req.auth` is
 * available without casting across your entire app:
 * ```ts
 * import type { AccessToken } from "@keycardai/oauth/server";
 * declare global {
 *   namespace Express {
 *     interface Request {
 *       auth?: AccessToken;
 *     }
 *   }
 * }
 * ```
 * We ship the interface-extension form rather than augmenting the global
 * namespace by default. Augmentation makes `req.auth` optional on every
 * request including unauthenticated routes, which weakens the type
 * contract. Use it when you prefer convenience over strictness.
 * See: https://github.com/auth0/express-jwt/issues/311
 */
export interface AuthenticatedRequest extends Request {
  auth: AccessToken;
}

export type BearerAuthOptions =
  | { verifier: TokenVerifier; requiredScopes?: readonly string[] }
  | {
      /**
       * Keycard zone URL, e.g. "https://zone-id.keycard.cloud".
       * Either `zoneUrl` or `zoneId` is required (consistent with `grant()`).
       */
      zoneUrl?: string;
      /**
       * Keycard zone ID. Constructs the URL as `https://{zoneId}.keycard.cloud`.
       * Either `zoneUrl` or `zoneId` is required (consistent with `grant()`).
       */
      zoneId?: string;
      audience?: string;
      enableMultiZone?: boolean;
      keyring?: TokenVerifierOptions["keyring"];
      requiredScopes?: readonly string[];
    };

/**
 * Express middleware that validates a Bearer token (RFC 6750) and sets
 * `req.auth` to the verified `AccessToken`.
 *
 * On failure: responds with a `WWW-Authenticate` challenge containing the
 * `resource_metadata` URL per RFC 9728 §3.
 *
 * Usage with a zone URL:
 * ```ts
 * app.use(requireBearerAuth({ zoneUrl: "https://zone.keycard.cloud" }));
 * // or by zone ID
 * app.use(requireBearerAuth({ zoneId: "zone-id" }));
 * ```
 *
 * Usage with a pre-built verifier (shared across routes):
 * ```ts
 * const verifier = new TokenVerifier({ issuer: "https://zone.keycard.cloud" });
 * app.use(requireBearerAuth({ verifier }));
 * ```
 */
export function requireBearerAuth(options: BearerAuthOptions): RequestHandler {
  // Do not pass requiredScopes to TokenVerifier: it returns null on scope
  // failure, which the middleware would interpret as a generic 401. The
  // explicit scope check below produces the correct 403 InsufficientScopeError.
  let verifier: TokenVerifier;
  if ("verifier" in options) {
    verifier = options.verifier;
  } else {
    const issuer = options.zoneUrl ?? buildIssuerFromZoneId(options.zoneId);
    if (!issuer) {
      throw new Error("requireBearerAuth: either `zoneUrl` or `zoneId` is required");
    }
    verifier = new TokenVerifier({
      issuer,
      audience: options.audience,
      enableMultiZone: options.enableMultiZone,
      keyring: options.keyring,
    });
  }

  return async (req: Request, res: Response, next: NextFunction) => {
    const resourceMetadataUrl = getResourceMetadataUrl(req);

    try {
      const authorization = req.headers.authorization;
      if (!authorization) {
        throw new UnauthorizedError("No credentials");
      }

      const [scheme, token] = authorization.split(" ");
      if (!token) {
        throw new BadRequestError("Malformed credentials");
      }
      if (scheme.toLowerCase() !== "bearer") {
        throw new InvalidTokenError("Unsupported authentication scheme");
      }

      const accessToken = await verifier.verifyToken(token);
      if (!accessToken) {
        throw new InvalidTokenError("Token validation failed");
      }

      // Validate resource audience: a token scoped to a different resource
      // server must not be accepted here. Compare origins so path and query
      // string differences are ignored (mirrors Workers auth.ts:88-92).
      if (accessToken.resource) {
        const requestOrigin = `${req.protocol}://${req.host}`;
        try {
          const tokenOrigin = new URL(accessToken.resource).origin;
          if (tokenOrigin !== requestOrigin) {
            throw new InvalidTokenError("Token not intended for resource");
          }
        } catch (e) {
          if (e instanceof InvalidTokenError) throw e;
          // resource claim is not a URL; opaque audience, skip origin check
        }
      }

      if (
        "requiredScopes" in options &&
        options.requiredScopes &&
        options.requiredScopes.length > 0
      ) {
        const hasAllScopes = options.requiredScopes.every((scope) =>
          accessToken.scopes.includes(scope),
        );
        if (!hasAllScopes) {
          throw new InsufficientScopeError("Insufficient scope");
        }
      }

      (req as AuthenticatedRequest).auth = accessToken;
      next();
    } catch (error) {
      if (error instanceof BadRequestError) {
        res.status(400).end();
      } else if (error instanceof UnauthorizedError) {
        res.set("WWW-Authenticate", `Bearer resource_metadata="${resourceMetadataUrl}"`);
        res.status(401).end();
      } else if (error instanceof InsufficientScopeError) {
        res.set(
          "WWW-Authenticate",
          `Bearer error="${(error as OAuthError).errorCode}", error_description="${error.message}", resource_metadata="${resourceMetadataUrl}"`,
        );
        res.status(403).end();
      } else if (error instanceof OAuthError || error instanceof InvalidTokenError) {
        res.set(
          "WWW-Authenticate",
          `Bearer error="${(error as OAuthError).errorCode}", error_description="${error.message}", resource_metadata="${resourceMetadataUrl}"`,
        );
        res.status(401).end();
      } else {
        next(error);
      }
    }
  };
}

function getResourceMetadataUrl(req: Request): string {
  const origin = `${req.protocol}://${req.host}`;
  return `${origin}/.well-known/oauth-protected-resource`;
}

function buildIssuerFromZoneId(zoneId?: string): string | undefined {
  if (!zoneId) return undefined;
  return `https://${zoneId}.keycard.cloud`;
}
