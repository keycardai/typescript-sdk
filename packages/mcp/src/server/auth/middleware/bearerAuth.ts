import type { Request, Response, NextFunction, RequestHandler } from "express";
import type { AuthInfo, OAuthTokenVerifier } from "../../../shared/auth.js";
import { omitWhenPrinted } from "../../../shared/printed.js";
import { makeJWTAccessTokenVerifier, toResourceUrl } from "../verifiers/jwt.js";
import { JWKSOAuthKeyring } from "@keycardai/oauth/keyring";
import { ConfigurationError } from "@keycardai/oauth/errors";
import { getOAuthProtectedResourceMetadataUrl } from "../router.js"
import { BadRequestError, UnauthorizedError, InvalidTokenError, InsufficientScopeError, HTTPError, OAuthError, JWKSError, JWKSKeyNotFoundError } from "../errors.js";
import { bearerChallenge, metadataChallenge, requestTarget, resolveResourceBinding, validateAudience, warnLegacy, zoneIssuers, type ResourceBindingOptions } from "../resourceBinding.js";

export interface AuthenticatedRequest extends Request {
  auth: AuthInfo;
}

function withBoundResource(authInfo: AuthInfo, identifier: string): AuthInfo {
  const inspectCustom = Symbol.for("nodejs.util.inspect.custom");
  const descriptors: PropertyDescriptorMap = Object.getOwnPropertyDescriptors(authInfo);
  const { resource: _resource, [inspectCustom]: _inspect, ...fields } = descriptors;
  const bound: AuthInfo = Object.create(Object.getPrototypeOf(authInfo), fields);
  Object.defineProperty(bound, "resource", { value: toResourceUrl(identifier), enumerable: true });
  const result = new Proxy(bound, {
    get(target, property) {
      if (property === "resource" || property === inspectCustom) return Reflect.get(target, property);
      return Reflect.get(authInfo, property);
    },
  });
  return omitWhenPrinted(result, "AuthInfo", ["token"]);
}

export type BearerAuthMiddlewareOptions = ResourceBindingOptions & {
  /**
   * Token verifier implementation. If omitted, a `JWTOAuthTokenVerifier` is
   * constructed from `issuers` / `audiences`. Exactly one of `verifier` or
   * `issuers` must be provided.
   */
  verifier?: OAuthTokenVerifier & { verifyAccessTokenForZone?(token: string, zone: string): Promise<AuthInfo> };
  /**
   * Issuer(s) to trust when auto-constructing the default verifier. Tokens
   * whose `iss` doesn't match are rejected before any key lookup.
   */
  issuers?: string | readonly string[];
  /**
   * Audience(s) to enforce when auto-constructing the default verifier. When
   * set, tokens must present an `aud` that contains one of these values.
   *
   * Also used by the resource check: a token whose resource is an http(s) URL
   * must share the request's origin, and a token whose resource is any other
   * identifier (for example a URN such as `urn:my-service`) is accepted only
   * when that identifier is one of these audiences.
   */
  audiences?: string | readonly string[];
  /** Selects a zone from the request without reading the bearer token. */
  zoneResolver?: (req: Request) => string | undefined;
  requiredScopes?: string[];
};

export function requireBearerAuth(options: BearerAuthMiddlewareOptions): RequestHandler {
  const { verifier, issuers, audiences, requiredScopes = [], zoneResolver } = options;
  const binding = resolveResourceBinding(options);
  validateAudience(binding, audiences);
  if (binding.mode === "perZone" && (!zoneResolver || (verifier && !verifier.verifyAccessTokenForZone))) {
    throw new ConfigurationError("Per-zone resource binding requires a token-independent zoneResolver and zone-scoped verification");
  }
  if (binding.mode === "shared" && zoneResolver) {
    throw new ConfigurationError("Shared discovery selects a trusted issuer from the token, not a zoneResolver");
  }
  let verify: (token: string, zone?: string) => Promise<AuthInfo>;
  if (verifier) {
    verify = (token, zone) => zone ? verifier.verifyAccessTokenForZone!(token, zone) : verifier.verifyAccessToken(token);
  } else if (binding.mode === "perZone" || binding.mode === "shared") {
    if (typeof issuers !== "string" || !issuers) {
      throw new ConfigurationError("Zone resource binding requires a single base issuer URL");
    }
    const configuredIssuers = zoneIssuers(binding, issuers);
    const keyring = new JWKSOAuthKeyring();
    if (binding.mode === "perZone") {
      const verifiers = new Map([...binding.entries].map(([zone, identifier]) => [
        zone, makeJWTAccessTokenVerifier(keyring, { issuers: configuredIssuers.get(zone)!, audiences: identifier.value }),
      ]));
      verify = (token, zone) => verifiers.get(zone!)!.verifyAccessToken(token);
    } else {
      const jwt = makeJWTAccessTokenVerifier(keyring, { issuers: [...configuredIssuers.values()], audiences });
      verify = token => jwt.verifyAccessToken(token);
    }
  } else {
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
    const jwt = makeJWTAccessTokenVerifier(keyring, {
      issuers: configuredIssuers,
      audiences: binding.mode === "single" ? binding.identifier.value : audiences,
    });
    verify = token => jwt.verifyAccessToken(token);
  }
  if (binding.mode === "legacy") warnLegacy("requireBearerAuth", audiences);

  return async (req, res, next) => {
    let requestUrl: URL | undefined;
    let resourceMetadataUrl: string | undefined;

    try {
      if (binding.mode === "legacy") {
        requestUrl = parseRequestUrl(req);
        resourceMetadataUrl = getOAuthProtectedResourceMetadataUrl(requestUrl);
      }
      const zone = binding.mode === "perZone" ? zoneResolver?.(req) : undefined;
      const identifier = binding.mode === "perZone"
        ? (zone ? binding.entries.get(zone) : undefined)
        : binding.mode === "single" || binding.mode === "shared" ? binding.identifier : undefined;
      if (binding.mode === "perZone" && !identifier) throw new UnauthorizedError("Unknown resource zone");
      if (binding.mode !== "legacy") resourceMetadataUrl = metadataChallenge(requestTarget(req.originalUrl), identifier);
      const credentials = req.headers.authorization;
      if (!credentials) {
        throw new UnauthorizedError("No credentials");
      }

      const [scheme, token, extra] = credentials.split(' ');
      if (!token || (binding.mode !== "legacy" && extra !== undefined)) {
        throw new BadRequestError("Malformed credentials");
      }
      if (scheme.toLowerCase() !== 'bearer') {
        throw new InvalidTokenError("Unsupported authentication scheme");
      }

      const authInfo = await verify(token, zone);
      const expected = identifier ? [identifier.value] : binding.mode === "multi" ? audiences as readonly string[] : undefined;
      if (expected) {
        const aud = authInfo.aud;
        const resourceHref = aud === undefined && verifier ? authInfo.resource?.href : undefined;
        const matches = aud !== undefined
          ? aud.some(value => expected.includes(value))
          : resourceHref !== undefined && expected.some(value => toResourceUrl(value)?.href === resourceHref);
        if (!matches) throw new InvalidTokenError("Audience mismatch");
      }

      if (authInfo.resource && requestUrl && !isIntendedResource(authInfo.resource, requestUrl, audiences)) {
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

      (req as Request & { auth?: AuthInfo }).auth = identifier
        ? withBoundResource(authInfo, identifier.value)
        : authInfo;
      next();
    } catch (error) {
      if (error instanceof BadRequestError || (binding.mode === "legacy" && !requestUrl)) {
        res.status(400).end();
        return;
      }

      if (error instanceof UnauthorizedError) {
        res.set("WWW-Authenticate", bearerChallenge(resourceMetadataUrl));
        res.status(401).end();
      } else if (error instanceof InvalidTokenError) {
        const challenge = bearerChallenge(resourceMetadataUrl, error.errorCode, error.message);
        res.set("WWW-Authenticate", challenge);
        res.status(401).end();
      } else if (error instanceof InsufficientScopeError) {
        const challenge = bearerChallenge(resourceMetadataUrl, error.errorCode, error.message);
        res.set("WWW-Authenticate", challenge);
        res.status(403).end();
      } else if (error instanceof JWKSKeyNotFoundError) {
        // A forged token, or a valid token whose signing key rotated out of the
        // JWKS: the resource server cannot validate it. RFC 6750 invalid_token
        // so the client re-runs authorization rather than seeing a 500.
        const challenge = bearerChallenge(resourceMetadataUrl, "invalid_token", "Unable to verify token signing key");
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

/**
 * Whether a token's resource belongs to this server. An http(s) resource must
 * share the request's origin. Any other resource (a URN such as
 * `urn:my-service` parses as a URL whose origin is "null") cannot be compared
 * to the request, so it must exactly match a configured audience.
 */
function isIntendedResource(
  resource: URL,
  requestUrl: URL,
  audiences: string | readonly string[] | undefined,
): boolean {
  if (resource.protocol === "http:" || resource.protocol === "https:") {
    return resource.origin === requestUrl.origin;
  }
  const configured = typeof audiences === "string" ? [audiences] : audiences ?? [];
  return configured.some((audience) => normalizeIdentifier(audience) === resource.href);
}

function normalizeIdentifier(identifier: string): string {
  try {
    return new URL(identifier).href;
  } catch {
    return identifier;
  }
}

/**
 * Builds the request URL from the Express request. A Host header that does
 * not form a valid URL is a client error, answered with 400 like any other
 * malformed request.
 */
function parseRequestUrl(req: Request): URL {
  try {
    return new URL(`${req.protocol}://${req.host}${req.originalUrl}`);
  } catch {
    throw new BadRequestError("Malformed request URL");
  }
}
