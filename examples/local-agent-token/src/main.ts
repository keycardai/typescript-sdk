/**
 * Local agent token: get an access token for a third-party resource from the
 * Keycard agent on this machine, with no application credential.
 *
 * The program holds no client secret, refresh token, or session. It asks the
 * local Keycard agent over its Unix socket; the agent brokers the token with
 * the developer's own zone session and asks the developer to approve the
 * request the first time. It then sends a GET to the resource with the token
 * attached by a resource transport.
 *
 * Keycard setup:
 *
 *   1. Install the Keycard CLI and sign in to a zone (`keycard auth signin`).
 *   2. In that zone, register the resource (e.g. https://api.github.com) and
 *      link it to the provider that issues its tokens.
 *   3. Either run this program under `keycard run`, which hands it the
 *      per-session socket in KEYCARD_SOCKET:
 *
 *        keycard run -- node dist/main.js
 *
 *      or start the multi-zone daemon and name the org and zone:
 *
 *        keycard agent start
 *        KEYCARD_ORG=... KEYCARD_ZONE=... node dist/main.js
 *
 *   4. Approve the prompt the agent shows. A repeat request for the same
 *      resource and scopes is answered without a prompt.
 *
 * Configuration (environment variables):
 *
 *   KEYCARD_RESOURCE  Resource indicator to mint for (default https://api.github.com)
 *   KEYCARD_URL       URL to GET with the token (default https://api.github.com/user)
 *   KEYCARD_SCOPES    Space-separated scopes (optional)
 *   KEYCARD_ORG       Organization id, for the `keycard agent` daemon (optional)
 *   KEYCARD_ZONE      Zone id, for the `keycard agent` daemon (optional)
 *   KEYCARD_APP_ID    Application the program says it acts for (optional)
 *
 * Run, from this directory (builds @keycardai/oauth from source first):
 *
 *   (cd ../../packages/oauth && pnpm install && pnpm build)
 *   npm install && npm run build && keycard run -- npm start
 */

import {
  AgentTokenSource,
  NetworkError,
  isApplicationNotFound,
  isAuthorizationRequired,
  isDeclined,
  resourceTransport,
} from "@keycardai/oauth/agent";

// A short, non-sensitive prefix of the access token for display.
function preview(token: string): string {
  return token.length <= 6 ? token : token.slice(0, 6);
}

async function main(): Promise<void> {
  const resource = process.env.KEYCARD_RESOURCE || "https://api.github.com";
  const url = process.env.KEYCARD_URL || "https://api.github.com/user";
  const scopes = process.env.KEYCARD_SCOPES?.split(" ").filter(Boolean) ?? [];

  const source = new AgentTokenSource({
    workload: "local-agent-token example",
    org: process.env.KEYCARD_ORG,
    zone: process.env.KEYCARD_ZONE,
    appId: process.env.KEYCARD_APP_ID,
  });

  const token = await source.resourceToken(resource, { scopes });
  console.log(`Token for ${resource}: ${preview(token.accessToken)}...`);
  console.log(`  expires in: ${token.expiresIn ?? "never"} seconds`);
  console.log(`  scope:      ${token.scope?.join(" ") ?? "(not reported)"}`);

  const send = resourceTransport({ source, resource, scopes });
  const response = await send(url, { headers: { Accept: "application/json" } });
  console.log(`GET ${url}: ${response.status}`);
  console.log((await response.text()).slice(0, 500));
}

main().catch((error: unknown) => {
  if (isDeclined(error)) {
    console.error("The request was declined.");
  } else if (isApplicationNotFound(error)) {
    console.error("KEYCARD_APP_ID names no application in the zone.");
  } else if (isAuthorizationRequired(error)) {
    console.error(`Action needed first: ${(error as Error).message}`);
  } else if (error instanceof NetworkError) {
    console.error(error.message);
  } else {
    console.error(error);
  }
  process.exit(1);
});
