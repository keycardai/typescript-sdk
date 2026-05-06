import type { Request, Response, NextFunction, RequestHandler } from "express";
import { TokenExchangeClient } from "@keycardai/oauth/tokenExchange";
import { AccessContext } from "@keycardai/oauth/server/accessContext";
import type { ApplicationCredential } from "@keycardai/oauth/credentials";
import { OAuthError, AuthProviderConfigurationError } from "@keycardai/oauth/errors";
import type { AuthenticatedRequest } from "./bearerAuth.js";
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
   * Keycard zone ID. Constructs the zone URL as
   * `https://{zoneId}.keycard.cloud`.
   */
  zoneId?: string;
  /**
   * Application credential provider for authenticated token exchange.
   * When omitted, the bearer token is exchanged without client auth.
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
  const zoneUrl = options.zoneUrl ?? buildZoneUrl(options.zoneId);
  if (!zoneUrl) {
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

    let client: TokenExchangeClient;
    try {
      const auth = options.applicationCredential?.getAuth();
      client = new TokenExchangeClient(zoneUrl, auth ?? undefined);
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
          );
        } else {
          exchangeRequest = {
            subjectToken,
            resource,
            subjectTokenType: "urn:ietf:params:oauth:token-type:access_token" as const,
          };
        }
        tokens[resource] = await client.exchangeToken(exchangeRequest);
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
