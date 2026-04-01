# Cloudflare Worker MCP Server

A Cloudflare Worker protected by Keycard OAuth authentication with delegated access to external APIs via token exchange. Demonstrates `@keycardai/cloudflare` — the Workers-native equivalent of `@keycardai/mcp`.

## What This Example Shows

- Using `createKeycardWorker()` for automatic OAuth metadata + bearer auth
- Registering MCP tools on a Worker
- Isolate-safe token exchange with `IsolateSafeTokenCache`
- Both credential modes: `ClientSecret` and `WebIdentity` (private key JWT)

## Prerequisites

- **Node.js 18+** and **wrangler CLI** (`npm install -g wrangler`)
- **Cloudflare account** — sign up at [dash.cloudflare.com](https://dash.cloudflare.com)
- **Keycard account** — sign up at [console.keycard.ai](https://console.keycard.ai)
- **Configured zone** with an identity provider (Okta, Auth0, Google, etc.)
- **Cursor IDE** or another MCP-compatible client for testing

## Keycard Console Setup

### 1. Register GitHub as a Provider

1. Create a GitHub OAuth App at [github.com/settings/developers](https://github.com/settings/developers)
2. In Keycard Console, navigate to **Providers** → **Add Provider**
3. Configure:
   - **Provider Name:** `GitHub OAuth`
   - **Identifier:** `https://github.com`
   - **Client ID / Secret:** from your GitHub OAuth App

### 2. Create a GitHub API Resource

1. Navigate to **Resources** → **Create Resource**
2. Configure:
   - **Resource Name:** `GitHub API`
   - **Resource Identifier:** `https://api.github.com`
   - **Credential Provider:** Select `GitHub OAuth`
   - **Scopes:** `user:email`, `read:user`

### 3. Register This Worker as a Resource

1. Navigate to **Resources** → **Create Resource**
2. Configure:
   - **Resource Name:** `Cloudflare Worker MCP Server`
   - **Resource Identifier:** `https://your-worker.your-subdomain.workers.dev`
   - **Credential Provider:** `Keycard STS`
   - **Scopes:** `mcp:tools`
3. Go to the resource details → **Dependencies** tab
4. Click **Connect Resource** and select `GitHub API`

### 4. Create Application Credentials

1. Navigate to **Applications** → **Create Application**
2. Note the **Client ID** and **Client Secret**

## Install and Deploy

```bash
cd examples/cloudflare-worker
npm install
```

Edit `wrangler.jsonc` and set `KEYCARD_ISSUER` to your zone URL, `KEYCARD_RESOURCE_URL` to `https://api.github.com`.

### Option A: Client Credentials

```bash
wrangler secret put KEYCARD_CLIENT_ID
wrangler secret put KEYCARD_CLIENT_SECRET
```

### Option B: Web Identity (no client secret)

Generate a private key and store it as a Worker secret:

```bash
openssl genrsa 2048 | wrangler secret put KEYCARD_PRIVATE_KEY
```

The Worker automatically serves its public key at `/.well-known/jwks.json`. Register this URL in Keycard Console as the application's JWKS endpoint.

### Deploy

```bash
wrangler deploy
```

## Test with Cursor IDE

Add to your Cursor MCP settings (`~/.cursor/mcp_settings.json`):

```json
{
  "mcpServers": {
    "cloudflare-worker": {
      "url": "https://your-worker.your-subdomain.workers.dev/mcp"
    }
  }
}
```

Restart Cursor, connect the MCP server, complete the OAuth flow, then try:
- "Run the whoami tool"
- "Get my GitHub user info"

## Local Development

```bash
wrangler dev
```

Then test against `http://localhost:8787`.

## Environment Variables

| Variable | Description | Set via |
|---|---|---|
| `KEYCARD_ISSUER` | Keycard zone URL | `wrangler.jsonc` vars |
| `KEYCARD_RESOURCE_URL` | Upstream API URL for token exchange | `wrangler.jsonc` vars |
| `KEYCARD_CLIENT_ID` | Application client ID (Option A) | `wrangler secret put` |
| `KEYCARD_CLIENT_SECRET` | Application client secret (Option A) | `wrangler secret put` |
| `KEYCARD_PRIVATE_KEY` | PEM-encoded RSA private key (Option B) | `wrangler secret put` |

## Related

- [Hello World example](../hello-world-server/) — Express-based equivalent
- [Delegated Access example](../delegated-access/) — Express-based token exchange
- [`@keycardai/cloudflare` docs](https://docs.keycard.ai/sdk/cloudflare/) — full API reference
- [`@keycardai/mcp` docs](https://docs.keycard.ai/sdk/mcp/) — Express-based auth (same primitives, different runtime)
