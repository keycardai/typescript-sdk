# Hello World MCP Server

A minimal Express server protected by Keycard OAuth authentication. Demonstrates the basic setup for an MCP-compatible server with bearer token verification and OAuth metadata endpoints.

## What This Example Shows

- Mounting OAuth metadata endpoints (`.well-known/oauth-protected-resource`)
- Protecting routes with `requireBearerAuth` middleware
- Reading authenticated user info from the request

## Prerequisites

- **Node.js 18+**
- **Keycard account** — sign up at [console.keycard.ai](https://console.keycard.ai)
- **Configured zone** with an identity provider (Okta, Auth0, Google, etc.)
- **Cursor IDE** or another MCP-compatible client for testing

## Setup

### 1. Register a Resource in Keycard Console

1. Navigate to **Resources** in Keycard Console
2. Click **Create Resource**
3. Configure:
   - **Resource Name:** `Hello World MCP Server (Local Dev)`
   - **Resource Identifier:** `http://localhost:8080`
   - **Credential Provider:** Select `Keycard STS`
   - **Scopes:** Add `mcp:tools`
4. Click **Create**

### 2. Install and Build

```bash
cd examples/hello-world-server
npm install
npm run build
```

### 3. Run

```bash
KEYCARD_ZONE_URL=https://your-zone-id.keycard.cloud npm start
```

Replace `your-zone-id` with your actual zone ID from Keycard Console.

### 4. Test with Cursor IDE

Add to your Cursor MCP settings (`~/.cursor/mcp_settings.json`):

```json
{
  "mcpServers": {
    "hello-world": {
      "url": "http://localhost:8080"
    }
  }
}
```

Restart Cursor, connect the MCP server, complete the OAuth flow, then try asking Cursor to "run the whoami tool".

## Environment Variables

| Variable | Description | Default |
|---|---|---|
| `KEYCARD_ZONE_URL` | Your Keycard zone URL | `https://your-zone.keycard.cloud` |
| `PORT` | Server port | `8080` |

## Related

- [Delegated Access example](../delegated-access/) — extends this pattern with token exchange for external APIs
- [Root README](../../README.md) — full SDK documentation
- [`@keycardai/mcp` README](../../packages/mcp/README.md) — API reference for all middleware and providers
