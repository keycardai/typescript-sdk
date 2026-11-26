import type { Request, Response, NextFunction, RequestHandler } from "express";
import { inspect } from "node:util";
import { TokenVerifier } from "@keycardai/oauth/server/tokenVerifier";
import type { TokenVerifierOptions } from "@keycardai/oauth/server/tokenVerifier";
import type { AccessToken } from "@keycardai/oauth/server/accessToken";
import { configureBearerIntrospection, type BearerIntrospectionOptions } from "@keycardai/oauth/bearerIntrospection";
import { JWTVerifier } from "@keycardai/oauth/jwt/verifier";
import { JWKSOAuthKeyring } from "@keycardai/oauth/keyring";
import {
  BadRequestError,
  ConfigurationError,
  UnauthorizedError,
  InvalidTokenError,
  InsufficientScopeError,
  OAuthError,
  HTTPError,
  JWKSError,
  JWKSKeyNotFoundError,
} from "@keycardai/oauth/errors";
import { getRequestOrigin } from "./host.js";
import {
  bearerChallenge, metadataChallenge, requestTarget, resolveResourceBinding, validateAudience, warnLegacy, zoneIssuers,
  type Audience, type ResourceBinding, type ResourceBindingOptions,
} from "./resourceBinding.js";

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

export type BearerAuthOptions = ResourceBindingOptions & BearerIntrospectionOptions & { audience?: Audience } & (
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
    }
);

/**
 * Express middleware that validates a Bearer token (RFC 6750) and sets
 * `req.auth` to the verified `AccessToken`.
 *
 * Responses when the token is not accepted:
 * - 401 with a `WWW-Authenticate` challenge carrying the `resource_metadata`
 *   URL (RFC 9728 §3) when no credentials were sent or the token is invalid,
 *   including a `kid` absent from a JWKS that loaded.
 * - 403 `insufficient_scope` when `requiredScopes` are not all present.
 * - 503 `{"error":"temporarily_unavailable"}` with no `WWW-Authenticate` when
 *   the zone's signing keys or metadata could not be fetched or the status
 *   could not be checked by introspection.
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
  return bearerAuthHandler(options);
}

export function bearerAuthHandler(
  options: BearerAuthOptions,
  binding = resolveResourceBinding(options),
  warn = true,
): RequestHandler {
  const { audience, zoneResolver } = options;
  validateAudience(binding, audience);
  if (binding.mode === "perZone" && !zoneResolver) {
    throw new ConfigurationError("Per-zone resource binding requires a token-independent zoneResolver");
  }
  if (binding.mode === "shared" && zoneResolver) {
    throw new ConfigurationError("Shared discovery selects a trusted issuer from the token, not a zoneResolver");
  }
  // A multi-zone zoneUrl is the base domain, not a zone, so a discoverable
  // single identifier would advertise it as the authorization server.
  if ("enableMultiZone" in options && options.enableMultiZone &&
      binding.mode === "single" && binding.identifier.metadataUrl) {
    throw new ConfigurationError("enableMultiZone requires resourceIdentifiersByZone for an HTTP(S) resourceIdentifier");
  }
  const verify = configureVerifier(options, binding);
  const multiZone = binding.mode === "perZone" || binding.mode === "shared"
    ? binding.entries.size > 1
    : "verifier" in options ? options.verifier.isMultiZone : options.enableMultiZone ?? false;
  const introspect = configureBearerIntrospection(options, multiZone);
  if (binding.mode === "legacy" && warn) warnLegacy("requireBearerAuth", audience);

  return async (req: Request, res: Response, next: NextFunction) => {
    let resourceMetadataUrl: string | undefined;

    try {
      const zone = binding.mode === "perZone" ? zoneResolver?.(req) : undefined;
      const identifier = binding.mode === "perZone"
        ? (zone ? binding.entries.get(zone) : undefined)
        : binding.mode === "single" || binding.mode === "shared" ? binding.identifier : undefined;
      if (binding.mode === "perZone" && !identifier) throw new UnauthorizedError("Unknown resource zone");
      resourceMetadataUrl = binding.mode === "legacy"
        ? getResourceMetadataUrl(req)
        : metadataChallenge(requestTarget(req.originalUrl), identifier);

      const authorization = req.headers.authorization;
      if (!authorization) {
        throw new UnauthorizedError("No credentials");
      }

      const [scheme, token, extra] = authorization.split(" ");
      if (!token || (binding.mode !== "legacy" && extra !== undefined)) {
        throw new BadRequestError("Malformed credentials");
      }
      if (scheme.toLowerCase() !== "bearer") {
        throw new InvalidTokenError("Unsupported authentication scheme");
      }

      const zoneId = binding.mode === "perZone" ? zone : zoneResolver?.(req);
      const accessToken = await verify(token, zoneId);
      if (!accessToken) {
        throw new InvalidTokenError("Token validation failed");
      }

      const expected = identifier ? [identifier.value] : binding.mode === "multi" ? audience as readonly string[] : undefined;
      if (expected && !accessToken.aud?.some(value => expected.includes(value))) {
        throw new InvalidTokenError("Audience mismatch");
      }
      if (binding.mode === "legacy" && accessToken.resource) {
        const legacyAudience = typeof audience === "string" || isAudienceList(audience)
          ? audience
          : zoneId && audience && Object.prototype.hasOwnProperty.call(audience, zoneId) ? audience[zoneId] : undefined;
        if (!isIntendedResource(accessToken.resource, getRequestOrigin(req), legacyAudience)) {
          throw new InvalidTokenError("Token not intended for resource");
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

      if (introspect && !await introspect(accessToken.issuer, token)) {
        throw new InvalidTokenError("Token is inactive");
      }

      (req as AuthenticatedRequest).auth = accessToken;
      (req as unknown as Record<symbol, unknown>)[KEYCARD_ACCESS_TOKEN] = accessToken;
      next();
    } catch (error) {
      if (error instanceof BadRequestError) {
        res.status(400).end();
      } else if (error instanceof UnauthorizedError) {
        res.set("WWW-Authenticate", bearerChallenge(resourceMetadataUrl));
        res.status(401).end();
      } else if (error instanceof InsufficientScopeError) {
        res.set(
          "WWW-Authenticate",
          bearerChallenge(resourceMetadataUrl, error.errorCode, error.message),
        );
        res.status(403).end();
      } else if (error instanceof InvalidTokenError) {
        res.set(
          "WWW-Authenticate",
          bearerChallenge(resourceMetadataUrl, error.errorCode, error.message),
        );
        res.status(401).end();
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
        // verification failures are mapped in the branches above.
        next(error);
      }
    }
  };
}

function isAudienceList(audience?: Audience): audience is readonly string[] {
  return Array.isArray(audience);
}

function configureVerifier(
  options: BearerAuthOptions,
  binding: ResourceBinding,
): (token: string, zone?: string) => Promise<AccessToken | null> {
  if ("verifier" in options) {
    if (binding.mode === "perZone") {
      throw new ConfigurationError("Per-zone resource binding requires zoneUrl or zoneId instead of a pre-built verifier");
    }
    return (token, zone) => zone
      ? options.verifier.verifyTokenForZone(token, zone)
      : options.verifier.verifyToken(token);
  }
  const issuer = options.zoneUrl ?? buildIssuerFromZoneId(options.zoneId);
  if (!issuer) throw new ConfigurationError("requireBearerAuth: either zoneUrl or zoneId is required");
  const configuredIssuers = zoneIssuers(binding, issuer);
  if (binding.mode === "perZone") {
    const keyring = options.keyring ?? new JWKSOAuthKeyring();
    const verifiers = new Map([...binding.entries].map(([zone, identifier]) => [
      zone, new TokenVerifier({ issuer: configuredIssuers.get(zone)!, audience: identifier.value, keyring }),
    ]));
    return async (token, zone) => (zone && verifiers.get(zone)?.verifyToken(token)) || null;
  }
  const audiences = binding.mode === "single" ? binding.identifier.value : options.audience;
  if (audiences !== undefined && binding.mode !== "shared") {
    const verifier = new TokenVerifier({
      issuer,
      audience: audiences,
      enableMultiZone: options.enableMultiZone,
      keyring: options.keyring,
    });
    return (token, zone) => zone ? verifier.verifyTokenForZone(token, zone) : verifier.verifyToken(token);
  }

  const sharedIssuers = binding.mode === "shared" ? [...configuredIssuers.values()] : undefined;
  const keyring = options.keyring ?? new JWKSOAuthKeyring();
  return async (token, zone) => {
    if (zone && !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(zone)) return null;
    const base = options.enableMultiZone && zone ? new URL(issuer) : undefined;
    const issuers = sharedIssuers ?? (base ? `${base.protocol}//${zone}.${base.host}` : issuer);
    const verifier = new JWTVerifier(keyring, {
      issuers,
      algorithms: ["RS256"],
      audiences: binding.mode === "shared" ? binding.identifier.value : undefined,
    });
    let claims: Awaited<ReturnType<JWTVerifier["verify"]>>;
    try {
      claims = await verifier.verify(token);
    } catch (error) {
      if (binding.mode === "legacy" && (error instanceof InvalidTokenError || error instanceof JWKSKeyNotFoundError)) {
        return null;
      }
      throw error;
    }
    const accessToken: AccessToken = {
      token,
      issuer: claims.iss,
      clientId: claims.client_id as string,
      scopes: typeof claims.scope === "string" ? claims.scope.split(" ").filter(Boolean) : [],
      expiresAt: claims.exp,
      resource: typeof claims.resource === "string" ? claims.resource : undefined,
      sub: typeof claims.sub === "string" ? claims.sub : undefined,
      subProfile: typeof claims.sub_profile === "string" ? claims.sub_profile : undefined,
      keycardAppId: typeof claims.keycard_app_id === "string" ? claims.keycard_app_id : undefined,
      aud: typeof claims.aud === "string" ? [claims.aud] : claims.aud ?? [],
      ...(claims.act !== null && typeof claims.act === "object" && !Array.isArray(claims.act)
        ? { act: claims.act as Record<string, unknown> }
        : {}),
    };
    return Object.defineProperty(accessToken, inspect.custom, {
      value(this: AccessToken, _depth: number, options: Parameters<typeof inspect>[1]) {
        const { token: _token, ...fields } = this;
        return "AccessToken " + inspect(fields, options);
      },
    });
  };
}

function getResourceMetadataUrl(req: Request): string {
  return `${getRequestOrigin(req)}/.well-known/oauth-protected-resource`;
}

/**
 * Whether a token's `resource` claim belongs to this server. A resource that
 * parses as an http(s) URL must share the request's origin. A resource that
 * does not parse as a URL is an opaque audience and is not compared. Any other
 * resource (a URN such as `urn:my-service` parses as a URL whose origin is
 * "null") must match one of the configured audiences.
 */
function isIntendedResource(
  resource: string,
  requestOrigin: string,
  audience: string | readonly string[] | undefined,
): boolean {
  let resourceUrl: URL;
  try {
    resourceUrl = new URL(resource);
  } catch {
    return true;
  }
  if (resourceUrl.protocol === "http:" || resourceUrl.protocol === "https:") {
    return resourceUrl.origin === requestOrigin;
  }
  return typeof audience === "string" ? audience === resource : audience?.includes(resource) ?? false;
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
 * subdomain to extract), is an IP address or localhost, or when the
 * leftmost label is not a DNS label (1 to 63 letters, digits, and
 * hyphens, not starting or ending with a hyphen). With no zone resolved
 * the middleware verifies against the configured base issuer.
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
  return DNS_LABEL.test(zoneId) ? zoneId : undefined;
}

const DNS_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;
