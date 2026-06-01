/**
 * Background Agent — user impersonation via Keycard token exchange (RFC 8693).
 *
 * A confidential client obtains a resource-scoped access token on behalf of a
 * named user, without the user being present. The user must have previously
 * granted access (a delegated grant) for the requested resource. Impersonation
 * is forbidden by default and must be explicitly permitted by server-side
 * Keycard policy.
 *
 * Under the hood `impersonate()` mints an actor token from this client's own
 * credentials (a client_credentials grant), then exchanges an unsigned
 * substitute-user assertion for a resource token whose `sub` is the target
 * user and whose `act` chain identifies this service for audit.
 *
 * Configuration (environment variables):
 *
 *   KEYCARD_ZONE_URL       Keycard zone URL for metadata discovery (required)
 *   KEYCARD_CLIENT_ID      Confidential client ID (required)
 *   KEYCARD_CLIENT_SECRET  Confidential client secret (required)
 *   KEYCARD_USER           Target user identifier, becomes "sub" (required)
 *   KEYCARD_RESOURCE       Target resource URI (optional)
 *   KEYCARD_SCOPES         Space-separated scopes (optional)
 *
 * See README.md for full setup instructions.
 *
 * Run:
 *   pnpm build && pnpm start
 */

import { TokenExchangeClient, OAuthError } from "@keycardai/oauth";

function required(name: string): string {
  const value = process.env[name];
  if (!value) {
    console.error(`Error: ${name} is required`);
    process.exit(1);
  }
  return value;
}

async function main(): Promise<void> {
  const zoneUrl = required("KEYCARD_ZONE_URL");
  const clientId = required("KEYCARD_CLIENT_ID");
  const clientSecret = required("KEYCARD_CLIENT_SECRET");
  const userIdentifier = required("KEYCARD_USER");
  const resource = process.env.KEYCARD_RESOURCE || undefined;
  const scopes = process.env.KEYCARD_SCOPES?.trim()
    ? process.env.KEYCARD_SCOPES.trim().split(/\s+/)
    : undefined;

  console.log("═══ Background Agent (impersonation) ═══");
  console.log("  Auth:            client_credentials");
  console.log(`  On behalf of:    ${userIdentifier}`);
  if (resource) console.log(`  Access resource: ${resource}`);
  console.log();

  const client = new TokenExchangeClient(zoneUrl, { clientId, clientSecret });

  try {
    const token = await client.impersonate({
      userIdentifier,
      resource,
      scopes,
    });

    console.log(`Access Token: ${token.accessToken.slice(0, 6)}...`);
    console.log(`Token Type:   ${token.tokenType}`);
    if (token.expiresIn) console.log(`Expires In:   ${token.expiresIn}s`);
    if (token.scope?.length)
      console.log(`Scope:        ${token.scope.join(" ")}`);
  } catch (err) {
    if (err instanceof OAuthError) {
      // invalid_grant: user unknown or not impersonatable by this client.
      // unauthorized_client: this client is not permitted to impersonate.
      console.error(`Error: OAuth error: ${err.errorCode} - ${err.message}`);
      process.exit(1);
    }
    throw err;
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
