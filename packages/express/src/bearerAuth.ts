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
  HTTPError,
  JWKSError,
  JWKSKeyNotFoundError,
} from "@keycardai/oauth/errors";
import { getRequestOrigin } from "./host.js";

/**
 * Provenance brand for downstream Keycard packages: `requireBearerAuth` stamps
 * this symbol on the request alongside `req.auth`, so consumers can confirm the
 * token was verified by this middleware; `req.auth` alone must not be treated
 * as Keycard-verified, since other middleware (notably express-jwt, whose
 * default `requestProperty` is also "auth") populates the same property.
 * Registry symbol (`Symbol.for`) so duplicate module instances agree.
 */
export const KEYCARD_ACCESS_TOKEN = Symbol.for("@keycardai/express.accessToken");

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
  | {
      verifier: TokenVerifier;
      requiredScopes?: readonly string[];
      zoneResolver?: (req: Request) => string | undefined;
    }
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
      /**
       * Resolves the zone ID for the incoming request. When it returns a
       * zone ID, the token is verified against that zone's issuer via
       * `TokenVerifier.verifyTokenForZone`; when it returns `undefined`
       * (or no resolver is set), the verifier's configured issuer is used.
       * Requires a multi-zone verifier (`enableMultiZone: true`).
       *
       * Multi-zone deployments where each zone is served on its own
       * subdomain can pass `subdomainZoneResolver` directly.
       */
      zoneResolver?: (req: Request) => string | undefined;
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

      const zoneId = options.zoneResolver?.(req);
      const accessToken = zoneId
        ? await verifier.verifyTokenForZone(token, zoneId)
        : await verifier.verifyToken(token);
      if (!accessToken) {
        throw new InvalidTokenError("Token validation failed");
      }

      // Validate resource audience: a token scoped to a different resource
      // server must not be accepted here. Compare origins so path and query
      // string differences are ignored (mirrors Workers auth.ts:88-92).
      if (accessToken.resource) {
        const requestOrigin = getRequestOrigin(req);
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
      (req as unknown as Record<symbol, unknown>)[KEYCARD_ACCESS_TOKEN] = accessToken;
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
          `Bearer error="${error.errorCode}", error_description="${error.message}", resource_metadata="${resourceMetadataUrl}"`,
        );
        res.status(403).end();
      } else if (error instanceof InvalidTokenError) {
        res.set(
          "WWW-Authenticate",
          `Bearer error="${error.errorCode}", error_description="${error.message}", resource_metadata="${resourceMetadataUrl}"`,
        );
        res.status(401).end();
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
        // verification failures are mapped in the branches above.
        next(error);
      }
    }
  };
}

function getResourceMetadataUrl(req: Request): string {
  return `${getRequestOrigin(req)}/.well-known/oauth-protected-resource`;
}

function buildIssuerFromZoneId(zoneId?: string): string | undefined {
  if (!zoneId) return undefined;
  return `https://${zoneId}.keycard.cloud`;
}

/**
 * Zone resolver that reads the zone ID from the leftmost label of the
 * request's Host header. Suited to multi-zone deployments where each zone
 * is served on its own subdomain, e.g. `zone-a.api.example.com` resolves
 * to zone `zone-a`:
 *
 * ```ts
 * app.use(requireBearerAuth({
 *   zoneUrl: baseZoneUrl,
 *   enableMultiZone: true,
 *   zoneResolver: subdomainZoneResolver,
 * }));
 * ```
 *
 * Returns `undefined` when the host has fewer than three labels (no
 * subdomain to extract) or is an IP address or localhost.
 */
export function subdomainZoneResolver(req: Request): string | undefined {
  const host = req.host;
  if (!host) return undefined;
  // Bracketed IPv6 literals carry no subdomain.
  if (host.startsWith("[")) return undefined;
  // req.host may still include a port on some Express versions; strip it.
  const hostname = host.split(":")[0];
  if (!hostname || hostname === "localhost") return undefined;
  // IPv4 literals carry no subdomain.
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) return undefined;
  const labels = hostname.split(".");
  if (labels.length < 3) return undefined;
  const zoneId = labels[0];
  return zoneId.length > 0 ? zoneId : undefined;
}
