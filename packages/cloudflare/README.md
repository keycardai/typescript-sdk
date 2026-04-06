# @keycardai/cloudflare

Keycard auth for Cloudflare Workers — bearer token verification, OAuth metadata endpoints, token exchange, and per-user token caching. **No Express dependency.**

This is the Workers equivalent of [`@keycardai/mcp`](../mcp/)'s server-side middleware. If you're building an Express server, use `@keycardai/mcp` instead.

## Installation

```bash
npm install @keycardai/cloudflare
```

`@keycardai/cloudflare` depends on `@keycardai/oauth` (included automatically).

## Quick Start

### One-Line Worker Setup

The fastest way to add Keycard auth to a Worker:

```typescript
import { createKeycardWorker } from "@keycardai/cloudflare";

export default createKeycardWorker({
  requiredScopes: ["read"],
  scopesSupported: ["read", "write"],
  resourceName: "My MCP Server",

  fetch(request, env, ctx, auth) {
    // auth is guaranteed — token is verified, scopes checked
    return new Response(JSON.stringify({
      message: `Hello ${auth.clientId}`,
      scopes: auth.scopes,
    }));
  },
});
```

`createKeycardWorker()` handles the full lifecycle: CORS preflight, `/.well-known/*` metadata endpoints, bearer token verification, then delegates to your handler.

### Environment Variables

Configure in `wrangler.toml` or the Cloudflare dashboard:

```toml
[vars]
KEYCARD_ISSUER = "https://your-zone.keycard.cloud"

# Option A: Client credentials
KEYCARD_CLIENT_ID = "your-client-id"
KEYCARD_CLIENT_SECRET = "your-client-secret"

# Option B: Web identity (private_key_jwt — no secret needed)
# KEYCARD_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\n..."
```

### Manual Setup

For more control, use the individual functions:

```typescript
import {
  verifyBearerToken,
  isAuthError,
  handleMetadataRequest,
} from "@keycardai/cloudflare";

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // 1. Serve OAuth metadata
    const metadata = await handleMetadataRequest(request, {
      issuer: env.KEYCARD_ISSUER,
      scopesSupported: ["read", "write"],
    });
    if (metadata) return metadata;

    // 2. Verify bearer token
    const auth = await verifyBearerToken(request, {
      requiredScopes: ["read"],
    });
    if (isAuthError(auth)) return auth; // 401/403 Response

    // 3. Use authenticated info
    return new Response(`Hello ${auth.subject}`);
  },
};
```

## Token Exchange with Caching

Exchange user tokens for upstream API tokens with per-user caching designed for Workers' shared-isolate model:

```typescript
import {
  createKeycardWorker,
  IsolateSafeTokenCache,
  resolveCredential,
} from "@keycardai/cloudflare";

let tokenCache: IsolateSafeTokenCache;

export default createKeycardWorker({
  requiredScopes: ["read"],

  async fetch(request, env, ctx, auth) {
    // Lazy-init cache (module-level state is safe across requests in Workers)
    if (!tokenCache) {
      tokenCache = new IsolateSafeTokenCache({
        zoneUrl: env.KEYCARD_ISSUER,
        credential: resolveCredential(env),
      });
    }

    // Exchange for upstream token (cached per-user, auto-refreshes)
    const upstream = await tokenCache.getToken(auth, env.KEYCARD_RESOURCE_URL!);

    const resp = await fetch("https://api.github.com/user", {
      headers: { Authorization: `Bearer ${upstream}` },
    });

    return new Response(resp.body, resp);
  },
});
```

`IsolateSafeTokenCache` handles:
- Per-user keying (`sub::resource`) for shared isolates
- In-flight deduplication (concurrent requests share one exchange)
- Skew-aware TTL (refreshes before expiry)
- Bounded size with LRU-ish eviction

## API

### `createKeycardWorker(options)`

Returns an `ExportedHandler` with Keycard auth built in. Auto-detects credential type from env.

### `verifyBearerToken(request, options?)`

Verifies a Bearer token. Returns `AuthInfo` on success or a `Response` (401/403) on failure.

### `handleMetadataRequest(request, options)`

Serves `/.well-known/oauth-protected-resource` and `/.well-known/oauth-authorization-server`. Returns `null` for non-metadata paths.

### `IsolateSafeTokenCache`

Per-user token exchange cache for Workers. See above for usage.

### `resolveCredential(env)`

Resolves `WorkersClientSecret` or `WorkersWebIdentity` from env bindings.

### `AuthInfo`

```typescript
interface AuthInfo {
  token: string;      // Raw bearer token
  clientId: string;   // client_id claim
  scopes: string[];   // Granted scopes
  expiresAt?: number; // Expiration (Unix seconds)
  resource?: URL;     // Audience/resource URL
  subject?: string;   // JWT sub claim
}
```

### Credential Types

| Type | Env vars | Auth method |
|---|---|---|
| `WorkersClientSecret` | `KEYCARD_CLIENT_ID` + `KEYCARD_CLIENT_SECRET` | Basic auth |
| `WorkersWebIdentity` | `KEYCARD_PRIVATE_KEY` | Private key JWT (RFC 7523) |
