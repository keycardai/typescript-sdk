import type { Request, Response, NextFunction, RequestHandler } from "express";
import { TokenExchangeClient } from "@keycardai/oauth/tokenExchange";
import { AccessContext } from "@keycardai/oauth/server/accessContext";
import type { ApplicationCredential } from "@keycardai/oauth/credentials";
import { OAuthError, AuthProviderConfigurationError } from "@keycardai/oauth/errors";
import type { AuthenticatedRequest } from "./bearerAuth.js";
import type { AccessToken } from "@keycardai/oauth/server/accessToken";
import type { TokenResponse } from "@keycardai/oauth/tokenExchange";

export interface GrantedRequest extends AuthenticatedRequest {
  accessContext: AccessContext;
}

export interface GrantOptions {
  /**
   * Keycard zone URL, e.g. "https://zone-id.keycard.cloud".
   * Either `zoneUrl` or `zoneId` is required.
   */
  zoneUrl?: string;
  /**
   * Keycard zone ID, or a function that resolves it from the verified
   * access token at request time. Use the function form for multi-zone
   * deployments where each request may target a different zone.
   *
   * ```ts
   * // Static zone
   * grant(resources, { zoneId: "zone-abc" });
   *
   * // Dynamic zone extracted from the token's clientId
   * grant(resources, { zoneId: (auth) => auth.clientId });
   * ```
   */
  zoneId?: string | ((auth: AccessToken) => string);
  /**
   * Application credential provider for authenticated token exchange.
   * For multi-zone deployments, pass a `ClientSecret` constructed with a
   * `Record<issuerUrl, [clientId, clientSecret]>` so the correct
   * credentials are selected per request by the zone's issuer URL.
   */
  applicationCredential?: ApplicationCredential;
  /**
   * Resolver for the user identity to impersonate. When set, each
   * per-resource exchange uses the substitute-user impersonation flow
   * (`TokenExchangeClient.impersonate`) with the resolved identifier
   * instead of exchanging the caller's bearer token. The resolver runs
   * once per request and may be async.
   *
   * ```ts
   * grant(resources, {
   *   zoneUrl,
   *   applicationCredential,
   *   userIdentifier: (req) => req.auth.subject,
   * });
   * ```
   */
  userIdentifier?: (req: Request) => string | Promise<string>;
}

/**
 * Express middleware factory for delegated token exchange (RFC 8693).
 *
 * Must run AFTER `requireBearerAuth()`. Reads the verified bearer token
 * from `req.auth`, exchanges it for per-resource access tokens at the
 * Keycard zone, and stores the results in `req.accessContext`.
 *
 * On success, `req.accessContext.access(resourceUrl)` returns the
 * `TokenResponse` for that resource. On partial failure, some resources
 * may have errors while others succeed.
 *
 * If the request carries no verified bearer token, responds 401 with an
 * RFC 6750 `WWW-Authenticate` challenge; the handler does not run.
 *
 * Multiple `grant()` middlewares may be stacked: each merges its
 * per-resource tokens and errors into the existing `req.accessContext`.
 *
 * ```ts
 * app.use(requireBearerAuth({ issuer: "https://zone.keycard.cloud" }));
 * app.use(grant(["https://graph.microsoft.com"], { zoneUrl: "https://zone.keycard.cloud" }));
 * app.get("/data", (req, res) => {
 *   const token = req.accessContext.access("https://graph.microsoft.com");
 *   // ...
 * });
 * ```
 */
export function grant(
  resources: string | readonly string[],
  options: GrantOptions,
): RequestHandler {
  // Validate at construction time that a zone is specified.
  const hasZoneOption = !!(options.zoneUrl || options.zoneId);
  if (!hasZoneOption) {
    throw new AuthProviderConfigurationError(
      "grant: either `zoneUrl` or `zoneId` is required",
    );
  }

  // Cache TokenExchangeClient instances keyed by resolved zone URL.
  // One client per zone amortizes AS discovery (GET /.well-known/) across
  // requests — the TokenExchangeClient already caches the token_endpoint
  // internally after the first discovery call.
  const clientCache = new Map<string, TokenExchangeClient>();

  return async (req: Request, res: Response, next: NextFunction) => {
    const authReq = req as AuthenticatedRequest;
    const subjectToken = authReq.auth?.token;

    if (!subjectToken) {
      // Unauthenticated request: respond 401 with an RFC 6750 challenge
      // (same shape as requireBearerAuth) without invoking the handler.
      const resourceMetadataUrl = `${req.protocol}://${req.host}/.well-known/oauth-protected-resource`;
      res.set("WWW-Authenticate", `Bearer resource_metadata="${resourceMetadataUrl}"`);
      res.status(401).json({
        error: "invalid_request",
        error_description:
          "Missing bearer token. Ensure requireBearerAuth() runs before grant().",
      });
      return;
    }

    // Reuse an existing context so stacked grant() middlewares accumulate
    // per-resource tokens and errors instead of replacing earlier results.
    const accessCtx =
      (req as GrantedRequest).accessContext instanceof AccessContext
        ? (req as GrantedRequest).accessContext
        : new AccessContext();

    // Resolve the zone at request time: zoneId may be a static string or a
    // function that extracts the zone from the verified access token. The
    // resolved zone composes the issuer URL used for token exchange and
    // per-zone credential selection.
    let resolvedZoneId: string | undefined;
    try {
      resolvedZoneId =
        typeof options.zoneId === "function"
          ? options.zoneId(authReq.auth)
          : options.zoneId;
    } catch (e) {
      return next(e);
    }

    const resolvedIssuer = options.zoneUrl ?? buildZoneUrl(resolvedZoneId);
    if (!resolvedIssuer) {
      accessCtx.setError({ message: "Could not resolve zone URL for this request." });
      (req as GrantedRequest).accessContext = accessCtx;
      return next();
    }

    // Look up or create a cached client for this zone.
    let client = clientCache.get(resolvedIssuer);
    if (!client) {
      // Pass the credential directly so TokenExchangeClient can call
      // getAuth(issuer) at exchange time, enabling multi-zone credential
      // routing without pre-resolving credentials here.
      client = new TokenExchangeClient(resolvedIssuer, {
        credential: options.applicationCredential,
      });
      clientCache.set(resolvedIssuer, client);
    }

    const resourceList = Array.isArray(resources)
      ? resources
      : [resources as string];
    const tokens: Record<string, TokenResponse> = {};

    // Resolve the impersonation target once per request. A resolver failure
    // is recorded as a global error; the handler still runs and access()
    // surfaces the failure.
    let resolvedUserIdentifier: string | undefined;
    if (options.userIdentifier) {
      try {
        resolvedUserIdentifier = await options.userIdentifier(req);
      } catch (e) {
        accessCtx.setError({
          message: "Failed to resolve userIdentifier.",
          rawError: String(e),
        });
        (req as GrantedRequest).accessContext = accessCtx;
        return next();
      }
    }

    for (const resource of resourceList) {
      try {
        if (resolvedUserIdentifier !== undefined) {
          tokens[resource] = await client.impersonate({
            userIdentifier: resolvedUserIdentifier,
            resource,
            issuer: resolvedIssuer,
          });
          continue;
        }
        let exchangeRequest;
        if (options.applicationCredential) {
          exchangeRequest = await options.applicationCredential.prepareTokenExchangeRequest(
            subjectToken,
            resource,
            { issuer: resolvedIssuer },
          );
        } else {
          exchangeRequest = {
            subjectToken,
            resource,
            subjectTokenType: "urn:ietf:params:oauth:token-type:access_token" as const,
          };
        }
        tokens[resource] = await client.exchangeToken(exchangeRequest, {
          issuer: resolvedIssuer,
        });
      } catch (e) {
        const detail: { message: string; code?: string; description?: string; rawError?: string } = {
          message: `Token exchange failed for ${resource}`,
        };
        if (e instanceof OAuthError) {
          detail.code = e.errorCode;
          detail.description = e.message;
        } else {
          detail.rawError = String(e);
        }
        accessCtx.setResourceError(resource, detail);
      }
    }

    accessCtx.setBulkTokens(tokens);
    (req as GrantedRequest).accessContext = accessCtx;
    next();
  };
}

function buildZoneUrl(zoneId?: string): string | undefined {
  if (!zoneId) return undefined;
  return `https://${zoneId}.keycard.cloud`;
}
