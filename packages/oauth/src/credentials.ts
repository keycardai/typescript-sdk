import type { TokenExchangeRequest } from "./tokenExchange.js";

/**
 * Common interface for application-level credentials used in token exchange.
 *
 * Implementations live in downstream packages (@keycardai/mcp, @keycardai/cloudflare)
 * because they depend on platform-specific APIs (Node.js fs, Cloudflare Workers, etc.).
 */
export interface ApplicationCredential {
  getAuth(): { clientId: string; clientSecret: string } | null;
  prepareTokenExchangeRequest(
    subjectToken: string,
    resource: string,
    options?: { tokenEndpoint?: string; authInfo?: Record<string, string> },
  ): Promise<TokenExchangeRequest>;
}
