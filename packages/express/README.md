# @keycardai/express

Keycard auth middleware for Express. Wraps Express's standard middleware idioms for protecting HTTP APIs with Keycard: bearer token validation (RFC 6750), delegated token exchange (RFC 8693), and OAuth discovery routes (RFC 9728 + RFC 8414).

## Installation

```bash
npm install @keycardai/express express
```

## Quick Start

### Protect routes with `requireBearerAuth`

```typescript
import express from "express";
import { requireBearerAuth, type AuthenticatedRequest } from "@keycardai/express";

const app = express();

app.use(requireBearerAuth({ zoneUrl: "https://your-zone.keycard.cloud" }));

app.get("/api/data", (req, res) => {
  // auth is AccessToken: { token, clientId, scopes, ... }
  const { auth } = req as AuthenticatedRequest;
  res.json({ clientId: auth.clientId });
});
```

Handlers behind `requireBearerAuth` cast to `AuthenticatedRequest` to type `req.auth`. If you prefer `req.auth` without casting across your entire app, adopt Express module augmentation instead; see the `AuthenticatedRequest` docs for the trade-off.

### Delegate tokens with `grant`

```typescript
import { requireBearerAuth, grant, type GrantedRequest } from "@keycardai/express";
import { ClientSecret } from "@keycardai/oauth/server";

const credential = new ClientSecret("your-client-id", "your-client-secret");

app.use(requireBearerAuth({ zoneUrl: "https://your-zone.keycard.cloud" }));
app.use(grant(["https://graph.microsoft.com"], {
  zoneUrl: "https://your-zone.keycard.cloud",
  applicationCredential: credential,
}));

app.get("/api/email", async (req, res) => {
  const { accessContext } = req as GrantedRequest;
  const token = accessContext.access("https://graph.microsoft.com");
  // use token.accessToken to call Graph API
  res.json({ ok: true });
});
```

For multi-zone deployments, pass a zone-keyed `ClientSecret` and resolve the zone from each request's verified token:

```typescript
import { requireBearerAuth, grant } from "@keycardai/express";
import { ClientSecret } from "@keycardai/oauth/server";

const credential = new ClientSecret({
  "zone-a": ["client-id-a", "client-secret-a"],
  "zone-b": ["client-id-b", "client-secret-b"],
});

app.use(requireBearerAuth({ zoneUrl: "https://base-zone.keycard.cloud", enableMultiZone: true }));

// zoneId accepts a function that receives the verified AccessToken and
// returns the zone identifier for this request. AccessToken has no
// dedicated zone field — use whichever field encodes zone context in
// your deployment (e.g. a zone-prefixed clientId, or a custom claim).
app.use(grant(["https://api.example.com"], {
  zoneId: (auth) => auth.clientId,
  applicationCredential: credential,
}));
```

### Add OAuth discovery routes

```typescript
import { keycardMetadataRouter } from "@keycardai/express";

app.use(keycardMetadataRouter({ issuer: "https://your-zone.keycard.cloud" }));
// Serves:
//   GET /.well-known/oauth-protected-resource  (RFC 9728)
//   GET /.well-known/oauth-authorization-server (RFC 8414, proxied)
```

## API

| Export | Description |
|---|---|
| `requireBearerAuth(options)` | Middleware factory that validates a Bearer token and sets `req.auth: AccessToken`. Returns 401 with RFC 6750 `WWW-Authenticate` challenge on failure. |
| `grant(resources, options)` | Middleware factory that exchanges the bearer token for per-resource access tokens and sets `req.accessContext: AccessContext`. Must run after `requireBearerAuth`. `zoneId` accepts a static string or a function `(auth: AccessToken) => string` for per-request zone resolution. |
| `keycardMetadataRouter(options)` | Returns an Express Router with `/.well-known/oauth-protected-resource` and `/.well-known/oauth-authorization-server` routes. |
| `createKeycardMiddleware(options)` | Factory that returns pre-configured `{ requireBearerAuth(), grant() }` sharing a single zone config. You still need `keycardMetadataRouter` for discovery routes. |
| `AuthenticatedRequest` | `Request` extended with `auth: AccessToken`. |
| `GrantedRequest` | `Request` extended with `auth: AccessToken` and `accessContext: AccessContext`. |

## Related Packages

- [`@keycardai/oauth`](../oauth/) — Framework-free OAuth primitives this package builds on
- [`@keycardai/mcp`](../mcp/) — MCP-specific OAuth integration
- [`@keycardai/a2a`](../a2a/) — Agent-to-agent (A2A) protocol integration
- [Keycard TypeScript SDK](../../README.md) — Root documentation
