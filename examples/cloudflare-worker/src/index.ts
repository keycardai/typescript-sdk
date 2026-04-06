/**
 * Cloudflare Worker MCP Server with Keycard Auth
 *
 * A minimal Worker protected by Keycard bearer auth with delegated
 * access to an external API via token exchange.
 *
 * Prerequisites:
 *   1. A Keycard zone with an identity provider configured
 *   2. A resource registered in Keycard Console for this Worker
 *   3. Application credentials (client ID + secret) or a private key
 *
 * See README.md for full setup instructions.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  createKeycardWorker,
  IsolateSafeTokenCache,
  resolveCredential,
} from "@keycardai/cloudflare";
import { TokenExchangeClient } from "@keycardai/oauth/tokenExchange";

interface Env {
  KEYCARD_ISSUER: string;
  KEYCARD_CLIENT_ID?: string;
  KEYCARD_CLIENT_SECRET?: string;
  KEYCARD_PRIVATE_KEY?: string;
  KEYCARD_RESOURCE_URL: string;
}

// Token cache is module-level but keyed by user identity — safe for isolate reuse
let tokenCache: IsolateSafeTokenCache | undefined;

function getTokenCache(env: Env): IsolateSafeTokenCache {
  if (!tokenCache) {
    const credential = resolveCredential(env);
    const client = new TokenExchangeClient(env.KEYCARD_ISSUER, credential.getAuth() ?? undefined);
    tokenCache = new IsolateSafeTokenCache(client, { credential });
  }
  return tokenCache;
}

export default createKeycardWorker<Env>({
  resourceName: "Cloudflare Worker Example",
  scopesSupported: ["mcp:tools"],
  requiredScopes: ["mcp:tools"],

  async fetch(request, env, ctx, auth) {
    const url = new URL(request.url);

    // Health check
    if (url.pathname === "/health") {
      return new Response(JSON.stringify({ status: "ok" }), {
        headers: { "Content-Type": "application/json" },
      });
    }

    // MCP server on /mcp
    if (url.pathname === "/mcp") {
      const server = new McpServer({ name: "Cloudflare Worker Example", version: "0.1.0" });

      // Simple tool: return authenticated user info
      server.tool("whoami", "Returns information about the authenticated user", {}, async () => {
        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              subject: auth.subject,
              clientId: auth.clientId,
              scopes: auth.scopes,
            }, null, 2),
          }],
        };
      });

      // Delegated access tool: fetch from upstream API using token exchange
      server.tool("github_user", "Fetches the authenticated user's GitHub profile", {}, async () => {
        const cache = getTokenCache(env);
        const token = await cache.getToken(auth.subject!, auth.token, env.KEYCARD_RESOURCE_URL);

        const response = await fetch("https://api.github.com/user", {
          headers: {
            Authorization: `Bearer ${token.accessToken}`,
            Accept: "application/vnd.github+json",
            "User-Agent": "keycard-worker-example",
          },
        });

        if (!response.ok) {
          const body = await response.text();
          return { content: [{ type: "text", text: `GitHub API error (${response.status}): ${body}` }] };
        }

        const user = await response.json() as Record<string, unknown>;
        return {
          content: [{
            type: "text",
            text: JSON.stringify({ login: user.login, name: user.name, email: user.email }, null, 2),
          }],
        };
      });

      const transport = new StreamableHTTPServerTransport("/mcp");
      await server.connect(transport);
      return transport.handleRequest(request);
    }

    return new Response("Not found", { status: 404 });
  },
});
