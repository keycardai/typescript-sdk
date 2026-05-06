# @keycardai/oauth

> **Preview.** This SDK has not reached parity with the Keycard Python
> SDK. APIs may change between minor versions. The preview label will
> be removed once feature parity is reached.

OAuth 2.0 primitives for Keycard: JWKS key management, JWT signing and verification, authorization server discovery, RFC 8693 token exchange (including impersonation), and server-tier primitives (`AccessContext`, `TokenVerifier`, `ClientSecret`) with multi-zone support. **Zero MCP dependencies.**

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

// Verify a JWT. `issuers` is required — it binds the verifier to the
// authorization server(s) you trust. Tokens with any other `iss` are
// rejected before the keyring is consulted.
const verifier = new JWTVerifier(keyring, {
  issuers: "https://your-zone.keycard.cloud",
  // audiences: "https://api.example.com", // optional
});
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

### Impersonation (substitute-user token exchange)

```typescript
import { TokenExchangeClient } from "@keycardai/oauth/tokenExchange";

const client = new TokenExchangeClient("https://your-zone.keycard.cloud", {
  clientId: "your-client-id",
  clientSecret: "your-client-secret",
});

const response = await client.impersonate({
  userIdentifier: "user@example.com",
  resource: "https://graph.microsoft.com",
});

console.log(response.accessToken);
```

Impersonation is a privileged operation gated by Keycard policy. The calling
application authenticates via client credentials, and the impersonated user
must have a delegated grant for the target resource.

### Multi-Zone Credentials

```typescript
import { TokenExchangeClient } from "@keycardai/oauth/tokenExchange";
import { ClientSecret } from "@keycardai/oauth/server";

const credential = new ClientSecret({
  "zone-a": ["client-id-a", "client-secret-a"],
  "zone-b": ["client-id-b", "client-secret-b"],
});

const client = new TokenExchangeClient("https://keycard.cloud", { credential });

const response = await client.exchangeToken(
  { subjectToken: userToken, resource: "https://api.example.com" },
  { zoneId: "zone-a" },
);
```

### Server-tier Token Verification

```typescript
import { TokenVerifier } from "@keycardai/oauth/server";

const verifier = new TokenVerifier({
  issuer: "https://your-zone.keycard.cloud",
  requiredScopes: ["read"],
  audience: "https://api.example.com",
});

const accessToken = await verifier.verifyToken(bearerToken);
if (!accessToken) {
  // 401 Unauthorized
}
console.log(accessToken.clientId, accessToken.scopes);
```

`verifyToken` returns `AccessToken | null`. Verification failures (bad signature,
expired token, missing scope, audience mismatch) return `null`; callers map that
to an HTTP 401. `verifyTokenForZone(token, zoneId)` enables per-zone validation
when the verifier is constructed with `enableMultiZone: true`.

### Dynamic Client Registration (RFC 7591)

```typescript
import { registerClient } from "@keycardai/oauth/registration";

const response = await registerClient("https://your-zone.keycard.cloud", {
  clientName: "My Service",
  redirectUris: ["https://app.example.com/callback"],
  grantTypes: ["client_credentials"],
  scope: "read write",
});

console.log(response.clientId, response.clientSecret);
```

`registerClient` discovers the AS's `registration_endpoint` from
`.well-known/oauth-authorization-server`, posts the request as JSON, and
returns the issued client credentials. Throws `OAuthError` on RFC 6749 §5.2
error responses, a plain `Error` on missing `registration_endpoint` or
non-OAuth HTTP failures.

### PKCE (RFC 7636)

```typescript
import {
  generateCodeVerifier,
  generateCodeChallenge,
  generatePkcePair,
  exchangeAuthorizationCode,
  authenticate,
} from "@keycardai/oauth/pkce";

// Generate primitives for a custom auth-code flow
const { codeVerifier, codeChallenge } = await generatePkcePair();

// Exchange code received at the redirect URI
const tokens = await exchangeAuthorizationCode(
  "https://your-zone.keycard.cloud",
  authorizationCode,
  { codeVerifier, redirectUri: "https://app.example.com/callback", clientId: "my-client" },
);

// Or let authenticate() drive the full flow (Node.js only)
const tokens2 = await authenticate("https://your-zone.keycard.cloud", {
  clientId: "my-client",
  scopes: ["read", "write"],
});
```

`generateCodeVerifier` and `generateCodeChallenge` use the global `crypto` API and
are runtime-agnostic (Node.js, Cloudflare Workers, browser). `authenticate()` drives
the full browser-launch and loopback-callback flow and **requires Node.js** — it uses
dynamic imports of `node:http` and `node:child_process` and will throw a runtime error
if called in a non-Node environment.

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
| `TokenExchangeClient` | `@keycardai/oauth/tokenExchange` | RFC 8693 token exchange client with auto-discovery, plus `impersonate()` for substitute-user exchange |
| `TokenType` | `@keycardai/oauth/tokenExchange` | URN constants: `ACCESS_TOKEN`, `SUBSTITUTE_USER` |
| `buildSubstituteUserToken` | `@keycardai/oauth/jwt/substituteUser` | Builds the unsigned subject JWT for impersonation calls |
| `registerClient` | `@keycardai/oauth/registration` | RFC 7591 dynamic client registration with auto-discovery |

### PKCE (RFC 7636)

| Export | Import Path | Description |
|---|---|---|
| `generateCodeVerifier` | `@keycardai/oauth/pkce` | Generates a 43-char random code verifier (RFC 7636 §4.1) |
| `generateCodeChallenge` | `@keycardai/oauth/pkce` | Computes S256 or plain code challenge from a verifier (RFC 7636 §4.2) |
| `generatePkcePair` | `@keycardai/oauth/pkce` | Convenience: generates verifier + challenge in one call |
| `exchangeAuthorizationCode` | `@keycardai/oauth/pkce` | Exchanges an authorization code with code_verifier at the token endpoint |
| `authenticate` | `@keycardai/oauth/pkce` | Full browser-launch and loopback-callback flow. **Node.js only** |
| `Pkce` (type) | `@keycardai/oauth/pkce` | `{ codeVerifier, codeChallenge, codeChallengeMethod }` |

### Server-tier Primitives

| Export | Import Path | Description |
|---|---|---|
| `TokenVerifier` | `@keycardai/oauth/server` | High-level JWT verifier with JWKS discovery, multi-zone, audience and scope validation; returns `AccessToken \| null` |
| `AccessToken` (type) | `@keycardai/oauth/server` | Verified token shape (`token`, `clientId`, `scopes`, `expiresAt?`, `resource?`) |
| `AccessContext` | `@keycardai/oauth/server` | Non-throwing per-resource token container with partial-error tracking |
| `ClientSecret` | `@keycardai/oauth/server` | Application credential provider; supports `(clientId, clientSecret)`, tuple, or `Record<zoneId, [id, secret]>` |
| `ApplicationCredential` (type) | `@keycardai/oauth/credentials` | Interface for credential providers |

### Errors

| Export | Import Path | Description |
|---|---|---|
| `HTTPError` | `@keycardai/oauth/errors` | Base HTTP error |
| `BadRequestError` | `@keycardai/oauth/errors` | 400 Bad Request |
| `UnauthorizedError` | `@keycardai/oauth/errors` | 401 Unauthorized |
| `OAuthError` | `@keycardai/oauth/errors` | OAuth error with error code and URI |
| `InvalidTokenError` | `@keycardai/oauth/errors` | Token validation failure |
| `InsufficientScopeError` | `@keycardai/oauth/errors` | Missing required scopes |
| `ResourceAccessError` | `@keycardai/oauth/errors` | Thrown by `AccessContext.access()` on missing or failed resource |
| `AuthProviderConfigurationError` | `@keycardai/oauth/errors` | Configuration guard for auth providers |

### Utilities

| Export | Import Path | Description |
|---|---|---|
| `base64url` | `@keycardai/oauth/base64url` | Base64url encode/decode utilities |

## Related Packages

- [`@keycardai/mcp`](../mcp/) — MCP-specific OAuth integration with Express middleware, bearer auth, and delegated access
- [`@keycardai/sdk`](../sdk/) — Aggregate package re-exporting from both oauth and mcp
- [Keycard TypeScript SDK](../../README.md) — Root documentation with full quick start guide
