# @keycardai/mcp

MCP-specific OAuth integration for Keycard — Express middleware for bearer token verification, OAuth metadata serving, delegated access via token exchange, and MCP client providers.

Builds on [`@keycardai/oauth`](../oauth/) (included as a dependency). Part of the [Keycard TypeScript SDK](../../README.md).

## Installation

```bash
npm install @keycardai/mcp
```

This includes `@keycardai/oauth` automatically.

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

### Delegated Access (Token Exchange)

Exchange a user's bearer token for resource-specific tokens to call external APIs on their behalf:

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
app.use(requireBearerAuth());

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
      "your-client-id",
    );
  }

  redirectToAuthorization(authorizationUrl: URL) {
    // Redirect user to authorization URL
    window.location.href = authorizationUrl.toString();
  }
}
```

## API Overview

### Server Auth Middleware

| Export | Import Path | Description |
|---|---|---|
| `requireBearerAuth` | `@keycardai/mcp/server/auth/middleware/bearerAuth` | Express middleware — verifies JWT bearer tokens, checks scopes, validates resource claims |
| `mcpAuthMetadataRouter` | `@keycardai/mcp/server/auth/router` | Express router for `.well-known/oauth-protected-resource` and `.well-known/oauth-authorization-server` |
| `JWTOAuthTokenVerifier` | `@keycardai/mcp/server/auth/verifiers/jwt` | Token verifier implementing the MCP SDK's `OAuthTokenVerifier` interface |

### Delegated Access

| Export | Import Path | Description |
|---|---|---|
| `AuthProvider` | `@keycardai/mcp/server/auth/provider` | Coordinates token exchange — use `.grant()` as Express middleware or `.exchangeTokens()` standalone |
| `AccessContext` | `@keycardai/mcp/server/auth/provider` | Result of a grant — contains tokens or errors per resource. Non-throwing by design |
| `DelegatedRequest` (type) | `@keycardai/mcp/server/auth/provider` | Express `Request` extended with `auth` and `accessContext` |

### Application Credentials

| Export | Import Path | Description |
|---|---|---|
| `ClientSecret` | `@keycardai/mcp/server/auth/credentials` | Client ID + secret authentication |
| `WebIdentity` | `@keycardai/mcp/server/auth/credentials` | Private key JWT authentication (RFC 7523) with file-based key storage |
| `EKSWorkloadIdentity` | `@keycardai/mcp/server/auth/credentials` | AWS EKS pod identity token authentication |
| `ApplicationCredential` (type) | `@keycardai/mcp/server/auth/credentials` | Interface for custom credential implementations |

### Client Auth

| Export | Import Path | Description |
|---|---|---|
| `BaseOAuthClientProvider` | `@keycardai/mcp/client/auth/providers/base` | Abstract base class implementing the MCP SDK's `OAuthClientProvider` interface |
| `JSONWebTokenSigner` | `@keycardai/mcp/client/auth/signers/jwt` | Signs authentication headers with JWT for client-side auth |

### Errors

| Export | Import Path | Description |
|---|---|---|
| `ResourceAccessError` | `@keycardai/mcp/server/auth/errors` | Token exchange failure for a specific resource |
| `AuthProviderConfigurationError` | `@keycardai/mcp/server/auth/errors` | Missing zone configuration |
| `EKSWorkloadIdentityConfigurationError` | `@keycardai/mcp/server/auth/errors` | EKS token file not found |

## AccessContext Error Handling

`AccessContext` never throws during token exchange. Errors are captured and queryable:

```typescript
const { accessContext } = req as DelegatedRequest;

const status = accessContext.getStatus(); // "success" | "partial_error" | "error"

if (accessContext.hasError()) {
  console.error(accessContext.getError()); // Global error (e.g., missing auth token)
}

if (accessContext.hasResourceError("https://api.github.com")) {
  console.error(accessContext.getResourceErrors("https://api.github.com"));
}

console.log("OK:", accessContext.getSuccessfulResources());
console.log("Failed:", accessContext.getFailedResources());
```

## Related Packages

- [`@keycardai/oauth`](../oauth/) — Pure OAuth 2.0 primitives (JWT, JWKS, discovery) without Express or MCP dependencies
- [`@keycardai/sdk`](../sdk/) — Aggregate package re-exporting from both oauth and mcp
- [Keycard TypeScript SDK](../../README.md) — Root documentation with full quick start and delegated access guide
