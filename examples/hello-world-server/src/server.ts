/**
 * Hello World MCP Server with Keycard OAuth
 *
 * A minimal Express server protected by Keycard bearer auth.
 * Serves OAuth metadata at .well-known endpoints and requires
 * a valid JWT for all /api routes.
 *
 * Prerequisites:
 *   1. A Keycard zone with an identity provider configured
 *   2. A resource registered in Keycard Console for this server
 *
 * See README.md for full setup instructions.
 */

import express from "express";
import { requireBearerAuth } from "@keycardai/mcp/server/auth/middleware/bearerAuth";
import { mcpAuthMetadataRouter } from "@keycardai/mcp/server/auth/router";

const ZONE_URL = process.env.KEYCARD_ZONE_URL ?? "https://your-zone.keycard.cloud";
const PORT = Number(process.env.PORT ?? 8080);

const app = express();

// Serve OAuth metadata at .well-known endpoints so MCP clients can discover auth.
app.use(
  mcpAuthMetadataRouter({
    oauthMetadata: { issuer: ZONE_URL },
    scopesSupported: ["mcp:tools"],
    resourceName: "Hello World MCP Server",
  }),
);

// Protect all /api routes with bearer token verification
app.use("/api", requireBearerAuth({ requiredScopes: ["mcp:tools"] }));

// A simple authenticated endpoint
app.get("/api/whoami", (req, res) => {
  const authReq = req as typeof req & { auth?: { token: string; clientId?: string; scopes?: string[] } };
  res.json({
    message: "Hello from Keycard!",
    authenticated: true,
    scopes: authReq.auth?.scopes,
  });
});

// Health check (no auth required)
app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

app.listen(PORT, () => {
  console.log(`Hello World MCP Server running on http://localhost:${PORT}`);
  console.log(`Zone: ${ZONE_URL}`);
  console.log(`Metadata: http://localhost:${PORT}/.well-known/oauth-protected-resource`);
});
