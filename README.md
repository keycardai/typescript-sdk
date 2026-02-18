# Keycard TypeScript SDK

A collection of TypeScript packages for Keycard services, organized as a pnpm workspace.

## Requirements

- **Node.js 18 or greater**
- **pnpm 9+**

## Packages

| Package | Description | npm |
|---|---|---|
| [`@keycardai/oauth`](packages/oauth/) | Pure OAuth 2.0 primitives — JWKS key management, JWT signing/verification, authorization server discovery | [![npm](https://img.shields.io/npm/v/@keycardai/oauth)](https://www.npmjs.com/package/@keycardai/oauth) |
| [`@keycardai/mcp`](packages/mcp/) | MCP OAuth integration — Express middleware, token verification, client providers | [![npm](https://img.shields.io/npm/v/@keycardai/mcp)](https://www.npmjs.com/package/@keycardai/mcp) |
| [`@keycardai/sdk`](packages/sdk/) | Aggregate package re-exporting from oauth + mcp | [![npm](https://img.shields.io/npm/v/@keycardai/sdk)](https://www.npmjs.com/package/@keycardai/sdk) |

## Installation

### For MCP Servers (Express)

If you're building an MCP server with Express:

```bash
npm install @keycardai/mcp
```

This includes `@keycardai/oauth` as a dependency.

### For OAuth Functionality Only

If you only need OAuth primitives (JWT signing, JWKS key management, discovery):

```bash
npm install @keycardai/oauth
```

### Aggregate Package

For convenience, you can install the aggregate package which re-exports from both:

```bash
npm install @keycardai/sdk
```

## Quick Start

### Protect an MCP Server with Bearer Auth

```typescript
import express from "express";
import { requireBearerAuth } from "@keycardai/mcp/server/auth/middleware/bearerAuth";
import { mcpAuthMetadataRouter } from "@keycardai/mcp/server/auth/router";

const app = express();

// Mount OAuth metadata endpoints (.well-known)
app.use(mcpAuthMetadataRouter("https://your-zone.keycard.ai"));

// Protect routes with bearer token verification
app.use("/api", requireBearerAuth({ requiredScopes: ["read"] }));

app.get("/api/data", (req, res) => {
  res.json({ message: "Authenticated!" });
});
```

### Sign and Verify JWTs

```typescript
import { JWTSigner } from "@keycardai/oauth/jwt/signer";
import { JWTVerifier } from "@keycardai/oauth/jwt/verifier";
import { JWKSOAuthKeyring } from "@keycardai/oauth/keyring";

// Sign a JWT
const keyring = new JWKSOAuthKeyring();
const signer = new JWTSigner(keyring);
const token = await signer.sign({
  sub: "user-123",
  aud: "https://api.example.com",
  scope: "read write",
});

// Verify a JWT
const verifier = new JWTVerifier(keyring);
const claims = await verifier.verify(token);
```

### MCP Client Provider

```typescript
import { BaseOAuthClientProvider } from "@keycardai/mcp/client/auth/providers/base";

class MyOAuthProvider extends BaseOAuthClientProvider {
  constructor() {
    super(
      {
        redirect_uris: [new URL("http://localhost:3000/callback")],
        client_name: "My MCP Client",
      },
      "your-client-id"
    );
  }

  redirectToAuthorization(authorizationUrl: URL) {
    // Redirect user to authorization URL
    window.location.href = authorizationUrl.toString();
  }
}
```

## Development

### Install from Source

```bash
git clone git@github.com:keycardai/typescript-sdk.git
cd typescript-sdk
pnpm install
```

### Build

```bash
pnpm run build
```

Packages build in dependency order: `oauth` first, then `mcp`, then `sdk`.

### Test

```bash
pnpm run test
```

### Type Check

```bash
pnpm run typecheck
```

## Architecture

The SDK mirrors the [Python SDK](https://github.com/keycardai/python-sdk) workspace structure:

```
packages/
  oauth/   → Pure OAuth 2.0 primitives (no MCP dependency)
  mcp/     → MCP-specific OAuth (depends on oauth + @modelcontextprotocol/sdk)
  sdk/     → Aggregate re-exports
```

`@keycardai/oauth` is the foundational layer with zero MCP dependencies. `@keycardai/mcp` builds on top for MCP-specific concerns (Express middleware, MCP SDK type adapters). Extensions for specific frameworks branch out from there.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

- GitHub Issues: [https://github.com/keycardai/typescript-sdk/issues](https://github.com/keycardai/typescript-sdk/issues)
- Documentation: [https://docs.keycard.ai](https://docs.keycard.ai/)
- Email: support@keycard.ai
