/**
 * Delegated Access MCP Server
 *
 * Demonstrates Keycard token exchange (RFC 8693): exchanging a user's
 * bearer token for a resource-specific token to call external APIs
 * on their behalf.
 *
 * This example exchanges the user's Keycard token for a GitHub API
 * token and fetches their profile.
 *
 * Prerequisites:
 *   1. A Keycard zone with an identity provider
 *   2. A GitHub OAuth provider registered in Keycard Console
 *   3. A GitHub API resource registered in Keycard Console
 *   4. This MCP server registered as a resource with GitHub API as a dependency
 *   5. Application credentials (client ID + secret) from Keycard Console
 *
 * See README.md for full setup instructions.
 */

import express from "express";
import { requireBearerAuth } from "@keycardai/mcp/server/auth/middleware/bearerAuth";
import { mcpAuthMetadataRouter } from "@keycardai/mcp/server/auth/router";
import { AuthProvider } from "@keycardai/mcp/server/auth/provider";
import { ClientSecret } from "@keycardai/mcp/server/auth/credentials";
import type { DelegatedRequest } from "@keycardai/mcp/server/auth/provider";

// Configuration from environment variables
const ZONE_URL = process.env.KEYCARD_ZONE_URL ?? "https://your-zone.keycard.cloud";
const CLIENT_ID = process.env.KEYCARD_CLIENT_ID ?? "your-client-id";
const CLIENT_SECRET = process.env.KEYCARD_CLIENT_SECRET ?? "your-client-secret";
const PORT = Number(process.env.PORT ?? 8080);

// Set up the auth provider for token exchange
const authProvider = new AuthProvider({
  zoneUrl: ZONE_URL,
  applicationCredential: new ClientSecret(CLIENT_ID, CLIENT_SECRET),
});

const app = express();

// Serve OAuth metadata at .well-known endpoints.
app.use(
  mcpAuthMetadataRouter({
    oauthMetadata: { issuer: ZONE_URL },
    scopesSupported: ["mcp:tools"],
    resourceName: "Delegated Access Example",
  }),
);

// Verify the user's bearer token on all /api routes
app.use("/api", requireBearerAuth({ requiredScopes: ["mcp:tools"] }));

// Fetch the authenticated user's GitHub profile via token exchange
app.get(
  "/api/github-user",
  authProvider.grant("https://api.github.com"),
  async (req, res) => {
    const { accessContext } = req as DelegatedRequest;

    // Check for token exchange errors
    if (accessContext.hasErrors()) {
      const errors = accessContext.getErrors();
      console.error("Token exchange failed:", errors);
      res.status(502).json({
        error: "Token exchange failed",
        details: errors,
      });
      return;
    }

    // Use the exchanged token to call GitHub API
    const token = accessContext.access("https://api.github.com").accessToken;

    const response = await fetch("https://api.github.com/user", {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/vnd.github+json",
      },
    });

    if (!response.ok) {
      res.status(response.status).json({
        error: "GitHub API error",
        status: response.status,
      });
      return;
    }

    const user = await response.json();
    res.json({
      login: user.login,
      name: user.name,
      email: user.email,
      public_repos: user.public_repos,
    });
  },
);

// Example: exchange for multiple resources at once
app.get(
  "/api/dashboard",
  authProvider.grant(["https://api.github.com", "https://api.slack.com"]),
  async (req, res) => {
    const { accessContext } = req as DelegatedRequest;

    const status = accessContext.getStatus();

    // Partial success: some resources may succeed while others fail
    if (status === "error") {
      res.status(502).json(accessContext.getErrors());
      return;
    }

    const result: Record<string, unknown> = { status };

    // Use whichever tokens succeeded
    for (const resource of accessContext.getSuccessfulResources()) {
      result[resource] = { tokenAvailable: true };
    }
    for (const resource of accessContext.getFailedResources()) {
      result[resource] = { error: accessContext.getResourceErrors(resource) };
    }

    res.json(result);
  },
);

// Health check (no auth required)
app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

app.listen(PORT, () => {
  console.log(`Delegated Access MCP Server running on http://localhost:${PORT}`);
  console.log(`Zone: ${ZONE_URL}`);
  console.log(`Endpoints:`);
  console.log(`  GET /api/github-user  — Fetch user's GitHub profile`);
  console.log(`  GET /api/dashboard    — Multi-resource token exchange`);
});
