import type { TokenExchangeRequest } from "./tokenExchange.js";

/**
 * Common interface for application-level credentials used in token exchange.
 *
 * Implementations live in downstream packages (@keycardai/mcp, @keycardai/cloudflare)
 * because they depend on platform-specific APIs (Node.js fs, Cloudflare Workers, etc.).
 *
 * The optional `zoneId` parameter routes per-zone credentials in multi-zone deployments.
 * Implementations that ignore the zone (single-zone) are accepted by the interface.
 */
export interface ApplicationCredential {
  getAuth(zoneId?: string): { clientId: string; clientSecret: string } | null;
  prepareTokenExchangeRequest(
    subjectToken: string,
    resource: string,
    options?: { tokenEndpoint?: string; authInfo?: Record<string, string>; zoneId?: string },
  ): Promise<TokenExchangeRequest>;
}
