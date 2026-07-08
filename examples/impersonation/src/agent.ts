/**
 * Background agent: user impersonation via Keycard token exchange (RFC 8693).
 *
 * A confidential client obtains a resource-scoped access token on behalf of
 * a named user, without the user being present. The user must have
 * previously granted access (a delegated grant) for the requested resource.
 * Impersonation is forbidden by default and must be explicitly permitted by
 * server-side Keycard policy.
 *
 * The exchange is authenticated with the client's own credentials, and the
 * subject token is an unsigned substitute-user assertion carrying the target
 * user identifier. The issued token's "sub" is the target user; the server
 * records this service in its "act" claim chain for audit.
 *
 * Configuration (environment variables):
 *
 *   KEYCARD_ZONE_URL       Keycard zone URL for metadata discovery (required)
 *   KEYCARD_CLIENT_ID      Confidential client ID (required)
 *   KEYCARD_CLIENT_SECRET  Confidential client secret (required)
 *   KEYCARD_USER           Target user identifier, becomes "sub" (required)
 *   KEYCARD_RESOURCE       Target resource URI (required)
 *   KEYCARD_SCOPES         Space-separated scopes (optional)
 *
 * See README.md for full setup instructions.
 *
 * Run:
 *   pnpm build && pnpm start
 */

import { TokenExchangeClient, OAuthError } from "@keycardai/oauth";

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    console.error(`Error: ${name} is required`);
    process.exit(1);
  }
  return value;
}

// A short, non-sensitive prefix of the access token for display.
function preview(token: string): string {
  return token.length <= 6 ? token : token.slice(0, 6);
}

async function main(): Promise<void> {
  const zoneUrl = requiredEnv("KEYCARD_ZONE_URL");
  const clientId = requiredEnv("KEYCARD_CLIENT_ID");
  const clientSecret = requiredEnv("KEYCARD_CLIENT_SECRET");
  const user = requiredEnv("KEYCARD_USER");
  const resource = requiredEnv("KEYCARD_RESOURCE");
  const scope = process.env.KEYCARD_SCOPES?.trim() || undefined;

  console.log("═══ Background Agent (impersonation) ═══");
  console.log("  Auth:            client_credentials");
  console.log(`  On behalf of:    ${user}`);
  console.log(`  Access resource: ${resource}`);
  console.log();

  const client = new TokenExchangeClient(zoneUrl, { clientId, clientSecret });

  const token = await client.impersonate({
    userIdentifier: user,
    resource,
    scope,
  });

  console.log(`Access Token: ${preview(token.accessToken)}...`);
  console.log(`Token Type:   ${token.tokenType}`);
  if (token.expiresIn !== undefined) {
    console.log(`Expires In:   ${token.expiresIn}s`);
  }
  if (token.scope?.length) {
    console.log(`Scope:        ${token.scope.join(" ")}`);
  }
}

main().catch((err: unknown) => {
  if (err instanceof OAuthError) {
    // invalid_grant: user unknown or not impersonatable by this client.
    // unauthorized_client: this client is not permitted to impersonate.
    console.error(`OAuth error: ${err.errorCode} - ${err.message}`);
  } else {
    console.error("impersonation failed:", err);
  }
  process.exit(1);
});
