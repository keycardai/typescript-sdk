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

  grant(resources: string | string[]): RequestHandler {
    return async (req: Request, _res: Response, next: NextFunction) => {
      const authReq = req as Request & { auth?: AuthInfo; accessContext?: AccessContext };
      const subjectToken = authReq.auth?.token;

      if (!subjectToken) {
        const accessCtx = new AccessContext();
        accessCtx.setError({
          message: "No authentication token available. Ensure requireBearerAuth() middleware runs before grant().",
        });
        authReq.accessContext = accessCtx;
        return next();
      }

      const accessCtx = await this.exchangeTokens(subjectToken, resources);
      authReq.accessContext = accessCtx;
      next();
    };
  }

  async exchangeTokens(subjectToken: string, resources: string | string[]): Promise<AccessContext> {
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
        let request;
        if (this.#applicationCredential) {
          const tokenEndpoint = undefined; // Let the client handle discovery
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
        const auth = this.#applicationCredential?.getAuth();
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
