# Delegated Access Example

An MCP server that demonstrates **token exchange** (RFC 8693) — exchanging a user's Keycard bearer token for resource-specific tokens to call external APIs on their behalf.

This example exchanges the user's token for a GitHub API token and fetches their profile. It also shows multi-resource token exchange with partial success handling.

## What This Example Shows

- Setting up `AuthProvider` with `ClientSecret` credentials
- Using `.grant()` middleware for single and multiple resources
- Reading tokens from `AccessContext`
- Handling partial success (`"partial_error"` status)
- Error handling patterns for token exchange failures

## Prerequisites

- **Node.js 18+**
- **Keycard account** — sign up at [console.keycard.ai](https://console.keycard.ai)
- **Configured zone** with an identity provider
- **GitHub OAuth App** (or any external OAuth provider)
- **Cursor IDE** or another MCP-compatible client

## Keycard Console Setup

### 1. Register GitHub as a Provider

1. Create a GitHub OAuth App at [github.com/settings/developers](https://github.com/settings/developers)
2. In Keycard Console, navigate to **Providers** → **Add Provider**
3. Configure:
   - **Provider Name:** `GitHub OAuth`
   - **Identifier:** `https://github.com`
   - **Authorization Endpoint:** `https://github.com/login/oauth/authorize`
   - **Token Endpoint:** `https://github.com/login/oauth/access_token`
   - **Client ID / Secret:** from your GitHub OAuth App
4. Copy the **OAuth Redirect URL** from Keycard and add it to your GitHub OAuth App's callback URLs

### 2. Create a GitHub API Resource

1. Navigate to **Resources** → **Create Resource**
2. Configure:
   - **Resource Name:** `GitHub API`
   - **Resource Identifier:** `https://api.github.com`
   - **Credential Provider:** Select `GitHub OAuth`
   - **Scopes:** `user:email`, `read:user`

### 3. Register This MCP Server as a Resource

1. Navigate to **Resources** → **Create Resource**
2. Configure:
   - **Resource Name:** `Delegated Access Example (Local Dev)`
   - **Resource Identifier:** `http://localhost:8080`
   - **Credential Provider:** `Keycard STS`
   - **Scopes:** `mcp:tools`
3. Go to the resource details → **Dependencies** tab
4. Click **Connect Resource** and select `GitHub API`

### 4. Create Application Credentials

1. Navigate to **Applications** → **Create Application**
2. Note the **Client ID** and **Client Secret**

## Install and Run

```bash
cd examples/delegated-access
npm install
npm run build
```

```bash
KEYCARD_ZONE_URL=https://your-zone-id.keycard.cloud \
KEYCARD_CLIENT_ID=your-client-id \
KEYCARD_CLIENT_SECRET=your-client-secret \
npm start
```

## Test with Cursor IDE

Add to your Cursor MCP settings (`~/.cursor/mcp_settings.json`):

```json
{
  "mcpServers": {
    "delegated-access": {
      "url": "http://localhost:8080"
    }
  }
}
```

Restart Cursor, connect the MCP server, complete the OAuth flow (including GitHub authorization), then try asking Cursor to "get my GitHub user info".

## Environment Variables

| Variable | Description | Default |
|---|---|---|
| `KEYCARD_ZONE_URL` | Your Keycard zone URL | `https://your-zone.keycard.cloud` |
| `KEYCARD_CLIENT_ID` | Application client ID | — |
| `KEYCARD_CLIENT_SECRET` | Application client secret | — |
| `PORT` | Server port | `8080` |

## Related

- [Hello World example](../hello-world-server/) — simpler example without token exchange
- [Root README — Delegated Access](../../README.md#delegated-access-token-exchange) — full documentation
- [`@keycardai/mcp` README](../../packages/mcp/README.md) — API reference for AuthProvider and AccessContext
