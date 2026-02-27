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

## Key Concepts

- **Zone** — A Keycard environment that groups your identity providers, MCP resources, and access policies. Get your zone ID from [console.keycard.ai](https://console.keycard.ai).
- **Delegated Access** — Calling external APIs (Google, GitHub, Slack, etc.) on behalf of your authenticated users via [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693) token exchange.
- **`.grant()` middleware** — Declares which external APIs a route needs. Automatically exchanges the user's token for a scoped token before your handler runs.
- **AccessContext** — The result of a grant. Contains exchanged tokens or errors. Non-throwing by design — always check `.hasErrors()` before using tokens.
- **Application Credentials** — How your server authenticates with Keycard for token exchange. Three types: `ClientSecret`, `WebIdentity` (private key JWT), `EKSWorkloadIdentity` (AWS EKS).

## Installation

### For MCP Servers (Express)

If you're building an MCP server with Express:

```bash
npm install @keycardai/mcp @modelcontextprotocol/sdk
```

`@keycardai/mcp` requires `@modelcontextprotocol/sdk` as a peer dependency (`^1.15.0`).
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
app.use(
  mcpAuthMetadataRouter({
    oauthMetadata: { issuer: "https://your-zone.keycard.cloud" },
  }),
);

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

## Examples

Runnable example projects with full setup instructions:

| Example | Description |
|---|---|
| [Hello World Server](examples/hello-world-server/) | Minimal MCP server with bearer auth and OAuth metadata |
| [Delegated Access](examples/delegated-access/) | Token exchange for external APIs (GitHub) with error handling |

## Delegated Access (Token Exchange)

The SDK supports OAuth 2.0 token exchange (RFC 8693) for delegated access — exchanging a user's bearer token for resource-specific tokens to call external APIs on behalf of authenticated users.

### Setup with Client Credentials

```typescript
import express from "express";
import { AuthProvider } from "@keycardai/mcp/server/auth/provider";
import { ClientSecret } from "@keycardai/mcp/server/auth/credentials";
import { requireBearerAuth } from "@keycardai/mcp/server/auth/middleware/bearerAuth";
import type { DelegatedRequest } from "@keycardai/mcp/server/auth/provider";

const authProvider = new AuthProvider({
  zoneUrl: "https://your-zone.keycard.cloud",
  applicationCredential: new ClientSecret("your-client-id", "your-client-secret"),
});

const app = express();

// 1. Verify the user's bearer token
app.use(requireBearerAuth());

// 2. Exchange for a resource-specific token
app.get(
  "/api/github-user",
  authProvider.grant("https://api.github.com"),
  async (req, res) => {
    const { accessContext } = req as DelegatedRequest;

    if (accessContext.hasErrors()) {
      return res.status(502).json(accessContext.getErrors());
    }

    const token = accessContext.access("https://api.github.com").accessToken;
    const response = await fetch("https://api.github.com/user", {
      headers: { Authorization: `Bearer ${token}` },
    });
    res.json(await response.json());
  },
);
```

### Error Handling

`AccessContext` never throws during token exchange — errors are captured and queryable:

```typescript
const { accessContext } = req as DelegatedRequest;

// Check overall status
const status = accessContext.getStatus(); // "success" | "partial_error" | "error"

// Check for global errors (e.g., missing auth token)
if (accessContext.hasError()) {
  console.error(accessContext.getError());
}

// Check for resource-specific errors
if (accessContext.hasResourceError("https://api.github.com")) {
  console.error(accessContext.getResourceErrors("https://api.github.com"));
}

// List successes and failures
console.log("OK:", accessContext.getSuccessfulResources());
console.log("Failed:", accessContext.getFailedResources());
```

### Multiple Resources

```typescript
app.get(
  "/api/dashboard",
  authProvider.grant(["https://api.github.com", "https://api.slack.com"]),
  async (req, res) => {
    const { accessContext } = req as DelegatedRequest;

    // Partial success: some resources may succeed while others fail
    if (accessContext.getStatus() === "partial_error") {
      // Handle gracefully — use what succeeded
    }

    const githubToken = accessContext.access("https://api.github.com").accessToken;
    const slackToken = accessContext.access("https://api.slack.com").accessToken;
    // ...
  },
);
```

### Standalone Usage (Without Express Middleware)

For non-Express contexts (e.g., MCP tool handlers), use `exchangeTokens()` directly:

```typescript
const accessContext = await authProvider.exchangeTokens(
  userBearerToken,
  "https://api.github.com",
);

if (accessContext.hasErrors()) {
  // Handle error
}

const token = accessContext.access("https://api.github.com").accessToken;
```

### WebIdentity (Private Key JWT)

For servers that authenticate with private key JWT (RFC 7523) instead of client secrets:

```typescript
import { AuthProvider } from "@keycardai/mcp/server/auth/provider";
import { WebIdentity } from "@keycardai/mcp/server/auth/credentials";

const authProvider = new AuthProvider({
  zoneUrl: "https://your-zone.keycard.cloud",
  applicationCredential: new WebIdentity({
    serverName: "My MCP Server",
    storageDir: "./mcp_keys", // RSA keys stored here
  }),
});
```

### EKS Workload Identity

For servers running on EKS with mounted pod identity tokens:

```typescript
import { AuthProvider } from "@keycardai/mcp/server/auth/provider";
import { EKSWorkloadIdentity } from "@keycardai/mcp/server/auth/credentials";

const authProvider = new AuthProvider({
  zoneUrl: "https://your-zone.keycard.cloud",
  applicationCredential: new EKSWorkloadIdentity(),
  // Discovers token from: KEYCARD_EKS_WORKLOAD_IDENTITY_TOKEN_FILE,
  // AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE, or AWS_WEB_IDENTITY_TOKEN_FILE
});
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

## Known Limitations & Non-Goals

### Current Limitations

- **Alpha Status**: All packages are in early development (`0.x.y`). APIs may change between minor versions.
- **Express Only**: Server-side middleware targets Express 5. Other frameworks (Fastify, Koa, Hono) are not supported yet.
- **MCP Protocol Version**: Requires `@modelcontextprotocol/sdk@^1.15.0` as a peer dependency. Compatible with any 1.x release from 1.15.0 onward.

### Non-Goals

- **Standalone Identity Provider**: These packages integrate with Keycard's hosted identity service, not standalone identity management.
- **TypeScript Only**: This SDK is TypeScript/JavaScript only. See the [Python SDK](https://github.com/keycardai/python-sdk) for Python.
- **Offline Operation**: All authentication flows require network connectivity to Keycard services.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

- GitHub Issues: [https://github.com/keycardai/typescript-sdk/issues](https://github.com/keycardai/typescript-sdk/issues)
- Documentation: [https://docs.keycard.ai](https://docs.keycard.ai/)
- Python SDK: [https://github.com/keycardai/python-sdk](https://github.com/keycardai/python-sdk)
- Email: support@keycard.ai
