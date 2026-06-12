import type { TokenExchangeRequest } from "./tokenExchange.js";

/**
 * Common interface for application-level credentials used in token exchange.
 *
 * Implementations live in downstream packages (@keycardai/mcp, @keycardai/cloudflare)
 * because they depend on platform-specific APIs (Node.js fs, Cloudflare Workers, etc.).
 *
 * The optional `issuer` parameter is the zone's issuer URL; it routes per-zone
 * credentials in multi-zone deployments. Implementations that ignore the issuer
 * (single-zone) are accepted by the interface.
 */
export interface ApplicationCredential {
  getAuth(issuer?: string): { clientId: string; clientSecret: string } | null;
  prepareTokenExchangeRequest(
    subjectToken: string,
    resource: string,
    options?: { tokenEndpoint?: string; authInfo?: Record<string, string>; issuer?: string },
  ): Promise<TokenExchangeRequest>;
}
