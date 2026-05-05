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
   * `Record<zoneId, [clientId, clientSecret]>` so the correct credentials
   * are selected per request.
   */
  applicationCredential?: ApplicationCredential;
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
  const hasStaticZone = !!(options.zoneUrl || options.zoneId);
  if (!hasStaticZone) {
    throw new AuthProviderConfigurationError(
      "grant: either `zoneUrl` or `zoneId` is required",
    );
  }

  return async (req: Request, _res: Response, next: NextFunction) => {
    const authReq = req as AuthenticatedRequest;
    const subjectToken = authReq.auth?.token;

    const accessCtx = new AccessContext();

    if (!subjectToken) {
      accessCtx.setError({
        message:
          "No authentication token. Ensure requireBearerAuth() runs before grant().",
      });
      (req as GrantedRequest).accessContext = accessCtx;
      return next();
    }

    // Resolve zone at request time — zoneId may be a static string or a
    // function that extracts the zone from the verified access token.
    const resolvedZoneId =
      typeof options.zoneId === "function"
        ? options.zoneId(authReq.auth)
        : options.zoneId;

    const resolvedZoneUrl = options.zoneUrl ?? buildZoneUrl(resolvedZoneId);
    if (!resolvedZoneUrl) {
      accessCtx.setError({ message: "Could not resolve zone URL for this request." });
      (req as GrantedRequest).accessContext = accessCtx;
      return next();
    }

    let client: TokenExchangeClient;
    try {
      // Pass the credential directly so TokenExchangeClient can call
      // getAuth(zoneId) at exchange time, enabling multi-zone credential
      // routing without pre-resolving credentials here.
      client = new TokenExchangeClient(resolvedZoneUrl, {
        credential: options.applicationCredential,
      });
    } catch (e) {
      accessCtx.setError({
        message: "Failed to initialize token exchange client.",
        rawError: String(e),
      });
      (req as GrantedRequest).accessContext = accessCtx;
      return next();
    }

    const resourceList = Array.isArray(resources)
      ? resources
      : [resources as string];
    const tokens: Record<string, TokenResponse> = {};

    for (const resource of resourceList) {
      try {
        let exchangeRequest;
        if (options.applicationCredential) {
          exchangeRequest = await options.applicationCredential.prepareTokenExchangeRequest(
            subjectToken,
            resource,
            { zoneId: resolvedZoneId },
          );
        } else {
          exchangeRequest = {
            subjectToken,
            resource,
            subjectTokenType: "urn:ietf:params:oauth:token-type:access_token" as const,
          };
        }
        tokens[resource] = await client.exchangeToken(exchangeRequest, {
          zoneId: resolvedZoneId,
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
