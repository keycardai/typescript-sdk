# @keycardai/oauth

Pure OAuth 2.0 primitives for Keycard — JWKS key management, JWT signing/verification, authorization server discovery, and token exchange. **Zero MCP dependencies.**

This is the foundational layer of the [Keycard TypeScript SDK](../../README.md). If you're building an MCP server, you probably want [`@keycardai/mcp`](../mcp/) instead, which includes this package as a dependency.

## Installation

```bash
npm install @keycardai/oauth
```

## Quick Start

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

### Discover Authorization Server Metadata

```typescript
import { fetchAuthorizationServerMetadata } from "@keycardai/oauth/discovery";

const metadata = await fetchAuthorizationServerMetadata(
  "https://your-zone.keycard.cloud",
);
console.log(metadata.token_endpoint);
console.log(metadata.jwks_uri);
```

### Token Exchange (RFC 8693)

```typescript
import { TokenExchangeClient } from "@keycardai/oauth/tokenExchange";

const client = new TokenExchangeClient("https://your-zone.keycard.cloud", {
  clientId: "your-client-id",
  clientSecret: "your-client-secret",
});

const response = await client.exchangeToken({
  subjectToken: userBearerToken,
  resource: "https://api.github.com",
});

console.log(response.accessToken);
```

## API Overview

### JWKS Key Management

| Export | Import Path | Description |
|---|---|---|
| `JWKSOAuthKeyring` | `@keycardai/oauth/keyring` | Fetches and caches JWKS public keys from an authorization server |
| `OAuthKeyring` (type) | `@keycardai/oauth/keyring` | Interface for public key lookup by issuer and key ID |
| `PrivateKeyring` (type) | `@keycardai/oauth/keyring` | Interface for private key access (signing) |

### JWT Signing & Verification

| Export | Import Path | Description |
|---|---|---|
| `JWTSigner` | `@keycardai/oauth/jwt/signer` | Signs JWTs with RS256 using a private keyring |
| `JWTVerifier` | `@keycardai/oauth/jwt/verifier` | Verifies JWT signatures against JWKS public keys |
| `JWTClaims` (type) | `@keycardai/oauth/jwt/signer` | Standard JWT claims (iss, sub, aud, exp, etc.) |

### Discovery & Token Exchange

| Export | Import Path | Description |
|---|---|---|
| `fetchAuthorizationServerMetadata` | `@keycardai/oauth/discovery` | Fetches `.well-known/oauth-authorization-server` metadata |
| `TokenExchangeClient` | `@keycardai/oauth/tokenExchange` | RFC 8693 token exchange client with auto-discovery |

### Errors

| Export | Import Path | Description |
|---|---|---|
| `HTTPError` | `@keycardai/oauth/errors` | Base HTTP error |
| `BadRequestError` | `@keycardai/oauth/errors` | 400 Bad Request |
| `UnauthorizedError` | `@keycardai/oauth/errors` | 401 Unauthorized |
| `OAuthError` | `@keycardai/oauth/errors` | OAuth error with error code and URI |
| `InvalidTokenError` | `@keycardai/oauth/errors` | Token validation failure |
| `InsufficientScopeError` | `@keycardai/oauth/errors` | Missing required scopes |

### Utilities

| Export | Import Path | Description |
|---|---|---|
| `base64url` | `@keycardai/oauth/base64url` | Base64url encode/decode utilities |

## Related Packages

- [`@keycardai/mcp`](../mcp/) — MCP-specific OAuth integration with Express middleware, bearer auth, and delegated access
- [`@keycardai/sdk`](../sdk/) — Aggregate package re-exporting from both oauth and mcp
- [Keycard TypeScript SDK](../../README.md) — Root documentation with full quick start guide
