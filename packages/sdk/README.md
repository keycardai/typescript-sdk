# @keycardai/sdk

> **Preview.** This SDK has not reached parity with the Keycard Python
> SDK. APIs may change between minor versions. The preview label will
> be removed once feature parity is reached.

Aggregate convenience package for the [Keycard TypeScript SDK](../../README.md). Installs and re-exports everything from [`@keycardai/oauth`](../oauth/) and [`@keycardai/mcp`](../mcp/) so you can use a single dependency.

## Installation

```bash
npm install @keycardai/sdk
```

## When to Use This Package

| Scenario | Recommended Package |
|---|---|
| Building an MCP server with Express | [`@keycardai/mcp`](../mcp/) (smaller footprint) |
| Only need JWT/JWKS/discovery | [`@keycardai/oauth`](../oauth/) (no MCP dependency) |
| Want everything in one install | **`@keycardai/sdk`** (this package) |

## What's Included

All public exports from both packages are available:

**From `@keycardai/oauth`:** `JWKSOAuthKeyring`, `JWTSigner`, `JWTVerifier`, `TokenExchangeClient`, `fetchAuthorizationServerMetadata`, error types, `base64url`

**From `@keycardai/mcp`:** `requireBearerAuth`, `mcpAuthMetadataRouter`, `AuthProvider`, `AccessContext`, `ClientSecret`, `WebIdentity`, `EKSWorkloadIdentity`, `BaseOAuthClientProvider`, `JSONWebTokenSigner`, `JWTOAuthTokenVerifier`

```typescript
// Everything from one import
import {
  requireBearerAuth,
  AuthProvider,
  ClientSecret,
  JWTSigner,
} from "@keycardai/sdk";
```

## Documentation

See the [root README](../../README.md) for quick start guides, delegated access patterns, and full usage examples. For detailed API references, see the individual package docs:

- [`@keycardai/oauth` README](../oauth/README.md) — JWT, JWKS, discovery, token exchange
- [`@keycardai/mcp` README](../mcp/README.md) — Express middleware, bearer auth, delegated access, client providers
