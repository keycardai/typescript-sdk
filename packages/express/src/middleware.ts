import type { RequestHandler } from "express";
import { requireBearerAuth } from "./bearerAuth.js";
import { grant } from "./grant.js";
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
}

export interface KeycardMiddleware {
  /**
   * Express middleware that validates a Bearer token and sets `req.auth`.
   * Accepts optional `requiredScopes` to enforce at the middleware level.
   */
  requireBearerAuth(options?: { requiredScopes?: readonly string[] }): RequestHandler;
  /**
   * Express middleware for delegated RFC 8693 token exchange.
   * Sets `req.accessContext` with per-resource tokens.
   */
  grant(
    resources: string | readonly string[],
    options?: {
      applicationCredential?: ApplicationCredential;
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
        requiredScopes: localOptions?.requiredScopes,
      });
    },

    grant(resources, localOptions) {
      return grant(resources, {
        zoneUrl,
        applicationCredential:
          localOptions?.applicationCredential ?? options.applicationCredential,
      });
    },
  };
}

function buildZoneUrl(zoneId?: string): string | undefined {
  if (!zoneId) return undefined;
  return `https://${zoneId}.keycard.cloud`;
}
