import type { Request, Response, NextFunction, RequestHandler } from "express";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { TokenExchangeClient } from "@keycardai/oauth/tokenExchange";
import type { TokenResponse } from "@keycardai/oauth/tokenExchange";
import { OAuthError } from "@keycardai/oauth/errors";
import { AuthProviderConfigurationError } from "./errors.js";
import type { ApplicationCredential } from "./credentials.js";
import { AccessContext } from "@keycardai/oauth/server/accessContext";
import type { ErrorDetail } from "@keycardai/oauth/server/accessContext";

// =============================================================================
// Types
// =============================================================================

export type { TokenResponse } from "@keycardai/oauth/tokenExchange";
export { AccessContext } from "@keycardai/oauth/server/accessContext";
export type { ErrorDetail, AccessContextStatus } from "@keycardai/oauth/server/accessContext";

export interface AuthProviderOptions {
  zoneUrl?: string;
  zoneId?: string;
  baseUrl?: string;
  applicationCredential?: ApplicationCredential;
}

export interface DelegatedRequest extends Request {
  auth: AuthInfo;
  accessContext: AccessContext;
}

export interface GrantMiddlewareOptions {
  /**
   * Resolver for the user identity to impersonate. When set, each
   * per-resource exchange uses the substitute-user impersonation flow
   * (`TokenExchangeClient.impersonate`) with the resolved identifier
   * instead of exchanging the caller's bearer token. The resolver runs
   * once per request and may be async.
   */
  userIdentifier?: (req: Request) => string | Promise<string>;
  /**
   * OAuth scopes to request for each per-resource token exchange. A single
   * string or string array applies to every resource. A record keys scopes
   * by resource string; resources absent from the record request no scope.
   * String arrays are joined with spaces for the wire `scope` parameter.
   */
  requestScopes?: string | string[] | Record<string, string | string[]>;
}

export interface ExchangeTokensOptions {
  /**
   * User identity to impersonate. When set, each per-resource exchange
   * uses the substitute-user impersonation flow instead of exchanging
   * the subject token.
   */
  userIdentifier?: string;
  /**
   * OAuth scopes to request for each per-resource token exchange. A single
   * string or string array applies to every resource. A record keys scopes
   * by resource string; resources absent from the record request no scope.
   */
  requestScopes?: string | string[] | Record<string, string | string[]>;
}

/**
 * Resolve the wire `scope` value for a single resource from the
 * `requestScopes` option. Returns undefined when no scope applies.
 */
function resolveRequestScope(
  requestScopes: string | string[] | Record<string, string | string[]> | undefined,
  resource: string,
): string | undefined {
  if (requestScopes === undefined) return undefined;
  if (typeof requestScopes === "string") return requestScopes;
  if (Array.isArray(requestScopes)) {
    return requestScopes.join(" ") || undefined;
  }
  const perResource = requestScopes[resource];
  if (perResource === undefined) return undefined;
  if (typeof perResource === "string") return perResource;
  return perResource.join(" ") || undefined;
}

// =============================================================================
// AuthProvider
// =============================================================================

export class AuthProvider {
  #zoneUrl: string;
  #applicationCredential?: ApplicationCredential;
  #client?: TokenExchangeClient;
  #clientPromise?: Promise<TokenExchangeClient>;

  constructor(options: AuthProviderOptions) {
    const zoneUrl = options.zoneUrl ?? this.#buildZoneUrl(options.zoneId, options.baseUrl);
    if (!zoneUrl) {
      throw new AuthProviderConfigurationError(
        "Either zoneUrl or zoneId must be provided",
      );
    }
    this.#zoneUrl = zoneUrl;
    this.#applicationCredential = options.applicationCredential;
  }

  grant(resources: string | string[], options?: GrantMiddlewareOptions): RequestHandler {
    return async (req: Request, res: Response, next: NextFunction) => {
      const authReq = req as Request & { auth?: AuthInfo; accessContext?: AccessContext };
      const subjectToken = authReq.auth?.token;

      if (!subjectToken) {
        // Unauthenticated request: respond 401 with an RFC 6750 challenge
        // (same shape as requireBearerAuth) without invoking the handler.
        const resourceMetadataUrl = `${req.protocol}://${req.host}/.well-known/oauth-protected-resource`;
        res.set("WWW-Authenticate", `Bearer resource_metadata="${resourceMetadataUrl}"`);
        res.status(401).json({
          error: "invalid_request",
          error_description:
            "Missing bearer token. Ensure requireBearerAuth() middleware runs before grant().",
        });
        return;
      }

      // Reuse an existing context so stacked grant() middlewares accumulate
      // per-resource tokens and errors instead of replacing earlier results.
      const existingCtx =
        authReq.accessContext instanceof AccessContext ? authReq.accessContext : undefined;

      // A resolver failure is recorded as a global error; the handler still
      // runs and access() surfaces the failure.
      let resolvedUserIdentifier: string | undefined;
      if (options?.userIdentifier) {
        try {
          resolvedUserIdentifier = await options.userIdentifier(req);
        } catch (e) {
          const accessCtx = existingCtx ?? new AccessContext();
          accessCtx.setError({
            message: "Failed to resolve userIdentifier.",
            rawError: String(e),
          });
          authReq.accessContext = accessCtx;
          return next();
        }
      }

      const accessCtx = await this.exchangeTokens(subjectToken, resources, {
        userIdentifier: resolvedUserIdentifier,
        requestScopes: options?.requestScopes,
      });
      if (existingCtx) {
        existingCtx.merge(accessCtx);
        authReq.accessContext = existingCtx;
      } else {
        authReq.accessContext = accessCtx;
      }
      next();
    };
  }

  async exchangeTokens(
    subjectToken: string,
    resources: string | string[],
    options?: ExchangeTokensOptions,
  ): Promise<AccessContext> {
    const accessCtx = new AccessContext();
    const resourceList = Array.isArray(resources) ? resources : [resources];

    let client: TokenExchangeClient;
    try {
      client = await this.#getOrCreateClient();
    } catch (e) {
      accessCtx.setError({
        message: "Failed to initialize OAuth client. Server configuration issue.",
        rawError: String(e),
      });
      return accessCtx;
    }

    const tokens: Record<string, TokenResponse> = {};

    for (const resource of resourceList) {
      try {
        const scope = resolveRequestScope(options?.requestScopes, resource);
        if (options?.userIdentifier !== undefined) {
          tokens[resource] = await client.impersonate({
            userIdentifier: options.userIdentifier,
            resource,
            scope,
          });
          continue;
        }
        let request;
        if (this.#applicationCredential) {
          const tokenEndpoint = await client.getTokenEndpoint();
          request = await this.#applicationCredential.prepareTokenExchangeRequest(
            subjectToken,
            resource,
            { tokenEndpoint },
          );
        } else {
          request = {
            subjectToken,
            resource,
            subjectTokenType: "urn:ietf:params:oauth:token-type:access_token" as const,
          };
        }
        if (scope !== undefined) {
          request = { ...request, scope };
        }

        const response = await client.exchangeToken(request);
        tokens[resource] = response;
      } catch (e) {
        const detail: ErrorDetail = {
          message: `Token exchange failed for ${resource}`,
        };
        if (e instanceof OAuthError) {
          detail.code = e.errorCode;
          if (e.message) {
            detail.description = e.message;
          }
        } else {
          detail.rawError = String(e);
        }
        accessCtx.setResourceError(resource, detail);
      }
    }

    accessCtx.setBulkTokens(tokens);
    return accessCtx;
  }

  async #getOrCreateClient(): Promise<TokenExchangeClient> {
    if (this.#client) return this.#client;

    if (!this.#clientPromise) {
      this.#clientPromise = (async () => {
        // The zone URL is the issuer, so issuer-keyed multi-zone
        // credentials resolve correctly for this provider's zone.
        const auth = this.#applicationCredential?.getAuth(this.#zoneUrl);
        const client = new TokenExchangeClient(this.#zoneUrl, auth ?? undefined);
        this.#client = client;
        return client;
      })();
    }

    return this.#clientPromise;
  }

  #buildZoneUrl(zoneId?: string, baseUrl?: string): string | undefined {
    if (!zoneId) return undefined;
    const base = baseUrl ?? "https://keycard.cloud";
    const url = new URL(base);
    return `${url.protocol}//${zoneId}.${url.host}`;
  }
}
