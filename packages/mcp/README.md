# @keycardai/mcp

> **Preview.** This SDK has not reached parity with the Keycard Python
> SDK. APIs may change between minor versions. The preview label will
> be removed once feature parity is reached.

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

// Protect routes with bearer token verification.
// `issuers` is required — it binds the verifier to your zone so forged
// tokens from any other issuer are rejected before key lookup.
app.use(
  "/api",
  requireBearerAuth({
    issuers: "https://your-zone.keycard.cloud",
    requiredScopes: ["read"],
  }),
);

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
app.use(requireBearerAuth({ issuers: "https://your-zone.keycard.cloud" }));

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

Implements the `OAuthClientProvider` interface from the MCP v2 client SDK
(`@modelcontextprotocol/client`, an optional peer dependency).

**Migrating from v1:** the client half now targets MCP v2, which shipped as a
package split rather than a version bump — there is no `@modelcontextprotocol/sdk`
2.x. Install the new client package alongside this one:

```bash
npm install @modelcontextprotocol/client
```

This applies equally if you consume `BaseOAuthClientProvider` through
`@keycardai/sdk`, which re-exports it. Without the package installed, the
provider's types resolve to `any` under `skipLibCheck` or fail with TS2307
without it. Consumers who need the v1 SDK should pin the previous
`@keycardai/mcp` minor instead; v1 and v2 are not supported side by side.

**Servers migrating to the v2 packages need zod 4.** This package keeps its
own zod 3 dependency (its v2 imports are type-only, so the majors coexist),
but that does not extend to your application code: v2's
`registerTool(name, { inputSchema })` types the zod overload against zod 4
internals, so a zod 3 schema fails to typecheck with a misleading
"missing properties from ZodType" error. Upgrade your app's zod to `^4`
when you move your server onto `@modelcontextprotocol/server`.

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
      {
        redirectUrl: "http://localhost:3000/callback",
      },
    );
  }

  redirectToAuthorization(authorizationUrl: URL) {
    // Redirect user to authorization URL
    window.location.href = authorizationUrl.toString();
  }
}
```

Notes on the v2 provider contract:

- `redirectUrl` returns `undefined` when no redirect URL is configured. The
  MCP SDK reads that as a non-interactive provider (`client_credentials`,
  `jwt-bearer`) and skips the authorization redirect leg.
- Token and client credential values persisted by the SDK carry an
  SDK-stamped authorization-server `issuer` field (`StoredOAuthTokens`,
  `StoredOAuthClientInformation`), and the persistence methods receive an
  optional context with the resolved issuer. The provider forwards that
  context to the configured `tokensStore`.
- Passing a `discoveryStateStore` in the options enables SEP-2352 discovery
  caching and the callback-leg authorization-server binding check. The store
  must persist with the same durability as the code verifier store: without
  it the SDK re-runs discovery on the callback leg and cannot verify that
  the authorization server matches the one recorded before the redirect.

### `req.auth` typing conflict with `@modelcontextprotocol/express`

The MCP v2 `@modelcontextprotocol/express` package globally augments
Express's `Request` interface with `auth?: AuthInfo` (the MCP SDK token
shape). Once that package is anywhere in your compilation, the
augmentation is active for every Express request type in the project.

This collides with `@keycardai/express`, which types `req.auth` as
Keycard's `AccessToken`:

- The `AuthenticatedRequest` interface (`auth: AccessToken`) extends the
  augmented `Request` whose `auth` is `AuthInfo | undefined`, which is
  TS2430 (incompatible member types: Keycard's `resource` is a string,
  the MCP shape's is a `URL`). With `skipLibCheck: true` the error inside
  the library declaration is suppressed and the
  `req as AuthenticatedRequest` cast pattern keeps working; declaring an
  equivalent interface in your own source surfaces the error.
- A user-level `declare global namespace Express` augmentation of
  `req.auth` as `AccessToken` does not error, it silently loses:
  the MCP package augments the more derived
  `express-serve-static-core` `Request`, so `req.auth` resolves to
  `AuthInfo | undefined` and Keycard token fields stop typechecking.

Workarounds until the two packages agree on a shared property: keep
`skipLibCheck: true` and the `AuthenticatedRequest` cast pattern instead
of global augmentation, or isolate the MCP express integration in a
separate TypeScript project so only one declaration of `req.auth` is in
scope per compilation.

## API Overview

### Server Auth Middleware

| Export | Import Path | Description |
|---|---|---|
| `requireBearerAuth` | `@keycardai/mcp/server/auth/middleware/bearerAuth` | Express middleware — verifies JWT bearer tokens, checks scopes, validates resource claims |
| `mcpAuthMetadataRouter` | `@keycardai/mcp/server/auth/router` | Express router for `.well-known/oauth-protected-resource` and `.well-known/oauth-authorization-server` |
| `JWTOAuthTokenVerifier` | `@keycardai/mcp/server/auth/verifiers/jwt` | Token verifier implementing the MCP SDK's `OAuthTokenVerifier` interface |
| `requireToolScopes`, `missingToolScopes` | `@keycardai/mcp/server/auth/toolScopes` | Per-tool scope checks inside MCP tool handlers via `ctx.http.authInfo` (route-level `requiredScopes` cannot vary per tool on a multiplexed `/mcp` route) |

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
