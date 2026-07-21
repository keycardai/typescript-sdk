import type { Request, RequestHandler } from "express";
import { requireBearerAuth } from "./bearerAuth.js";
import { grant } from "./grant.js";
import type { GrantOptions } from "./grant.js";
import type { ApplicationCredential } from "@keycardai/oauth/credentials";

export interface KeycardMiddlewareOptions {
  /**
   * Keycard zone URL, e.g. "https://zone-id.keycard.cloud".
   * Either `zoneUrl` or `zoneId` is required.
   */
  zoneUrl?: string;
  /**
   * Keycard zone ID. Constructs the URL as `https://{zoneId}.keycard.cloud`.
   */
  zoneId?: string;
  /**
   * Application credential for token exchange in `grant()`.
   * Typically a `ClientSecret` from `@keycardai/oauth/server`.
   */
  applicationCredential?: ApplicationCredential;
  /**
   * Audience to validate tokens against in `requireBearerAuth()`.
   */
  audience?: string;
  /**
   * Enables per-request zone verification in `requireBearerAuth()`.
   * Pair with `zoneResolver` for multi-zone deployments.
   */
  enableMultiZone?: boolean;
  /**
   * Resolves the zone ID for each incoming request in `requireBearerAuth()`.
   * Requires `enableMultiZone: true`. `subdomainZoneResolver` can be passed
   * directly for subdomain-per-zone deployments.
   */
  zoneResolver?: (req: Request) => string | undefined;
  /**
   * Resolver for the user identity to impersonate in `grant()`. When set,
   * each per-resource exchange uses the substitute-user impersonation flow
   * instead of exchanging the caller's bearer token. A per-call value
   * replaces this one, but a factory-level identifier cannot be unset per
   * call: every grant from this factory uses the impersonation flow. For a
   * plain exchange on one route, use the standalone `grant()` instead.
   */
  userIdentifier?: GrantOptions["userIdentifier"];
  /**
   * OAuth scopes to request for each per-resource token exchange in
   * `grant()`. Overridable per call.
   */
  requestScopes?: GrantOptions["requestScopes"];
}

export interface KeycardMiddleware {
  /**
   * Express middleware that validates a Bearer token and sets `req.auth`.
   * Accepts optional `requiredScopes` to enforce at the middleware level.
   */
  requireBearerAuth(options?: { requiredScopes?: readonly string[] }): RequestHandler;
  /**
   * Express middleware for delegated RFC 8693 token exchange.
   * Sets `req.accessContext` with per-resource tokens. Per-call options
   * override the factory-level defaults.
   */
  grant(
    resources: string | readonly string[],
    options?: {
      applicationCredential?: ApplicationCredential;
      userIdentifier?: GrantOptions["userIdentifier"];
      requestScopes?: GrantOptions["requestScopes"];
    },
  ): RequestHandler;
}

/**
 * Creates a pair of pre-configured Keycard middleware functions sharing a
 * common zone configuration: pass `zoneUrl`/`zoneId` and credentials once
 * and get `requireBearerAuth` and `grant` bound to that zone.
 *
 * Python equivalent: `AuthProvider(zone_url=..., application_credential=...)`
 *
 * ```ts
 * const keycard = createKeycardMiddleware({
 *   zoneUrl: "https://zone.keycard.cloud",
 *   applicationCredential: new ClientSecret("client-id", "client-secret"),
 * });
 *
 * app.use(keycard.requireBearerAuth());
 * app.use(keycard.grant(["https://graph.microsoft.com"]));
 * ```
 *
 * Multi-zone deployments configure verification and exchange the same way
 * they would with the standalone middlewares:
 * ```ts
 * const keycard = createKeycardMiddleware({
 *   zoneUrl: "https://keycard.cloud",
 *   enableMultiZone: true,
 *   zoneResolver: subdomainZoneResolver,
 *   applicationCredential: multiZoneClientSecret,
 * });
 * ```
 */
export function createKeycardMiddleware(options: KeycardMiddlewareOptions): KeycardMiddleware {
  const zoneUrl = options.zoneUrl ?? buildZoneUrl(options.zoneId);
  if (!zoneUrl) {
    throw new Error("createKeycardMiddleware: either `zoneUrl` or `zoneId` is required");
  }

  return {
    requireBearerAuth(localOptions?: { requiredScopes?: readonly string[] }) {
      return requireBearerAuth({
        zoneUrl,
        audience: options.audience,
        enableMultiZone: options.enableMultiZone,
        zoneResolver: options.zoneResolver,
        requiredScopes: localOptions?.requiredScopes,
      });
    },

    grant(resources, localOptions) {
      return grant(resources, {
        zoneUrl,
        applicationCredential:
          localOptions?.applicationCredential ?? options.applicationCredential,
        userIdentifier: localOptions?.userIdentifier ?? options.userIdentifier,
        requestScopes: localOptions?.requestScopes ?? options.requestScopes,
      });
    },
  };
}

function buildZoneUrl(zoneId?: string): string | undefined {
  if (!zoneId) return undefined;
  return `https://${zoneId}.keycard.cloud`;
}
