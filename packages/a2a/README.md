# @keycardai/a2a

> **Preview.** This SDK has not reached parity with the Keycard Python SDK. APIs may change between minor versions.

Keycard auth integration for the [Agent-to-Agent (A2A) protocol](https://google.github.io/A2A). Wraps [`@a2a-js/sdk`](https://github.com/a2aproject/a2a-js) the same way Python's `keycardai-a2a` wraps `a2a-sdk 1.x` — adds Keycard auth on top of the existing SDK's routing, executor, and task store infrastructure.

Python equivalent: [`keycardai-a2a`](https://github.com/keycardai/python-sdk/tree/main/packages/a2a).

## Installation

```bash
npm install @keycardai/a2a @a2a-js/sdk express
```

## Quick Start

### Build an A2A agent server

```typescript
import express from "express";
import { agentCardHandler, jsonRpcHandler } from "@a2a-js/sdk/server/express";
import { InMemoryTaskStore, type AgentExecutor, type RequestContext, type ExecutionEventBus } from "@a2a-js/sdk/server";
import {
  requireBearerAuth,
  keycardUserBuilder,
  getKeycardAuth,
  createKeycardRequestHandler,
  buildAgentCard,
} from "@keycardai/a2a";

const executor: AgentExecutor = {
  async execute(requestContext: RequestContext, eventBus: ExecutionEventBus) {
    const auth = getKeycardAuth(requestContext);
    if (!auth) throw new Error("unauthenticated"); // guard: requireBearerAuth normally prevents this
    // auth.token is the raw bearer string for downstream delegation
    const text = (requestContext.userMessage.parts[0] as any).text;
    eventBus.publish({ messageId: crypto.randomUUID(), role: "agent",
      parts: [{ kind: "text", text: `Hello: ${text}` }] } as any);
    eventBus.finished();
  },
  async cancelTask() {},
};

const config = {
  serviceName: "My Agent",
  clientId: process.env.KEYCARD_CLIENT_ID!,
  clientSecret: process.env.KEYCARD_CLIENT_SECRET!,
  identityUrl: "https://my-agent.example.com",
  zoneId: process.env.KEYCARD_ZONE_ID,
};

const agentCard = buildAgentCard(config);
const requestHandler = createKeycardRequestHandler(executor, agentCard);

const app = express();
app.use(express.json());
app.use("/.well-known/agent-card.json", agentCardHandler({ agentCardProvider: requestHandler }));
app.use(
  "/a2a/jsonrpc",
  // Rejects unauthenticated requests with 401 + WWW-Authenticate (RFC 6750)
  // and sets req.auth to the verified token.
  requireBearerAuth({
    zoneUrl: `https://${config.zoneId}.keycard.cloud`,
    // Recommended: leaving audience unset disables the audience check.
    audience: config.identityUrl,
  }),
  // Wraps the verified token from req.auth into a KeycardUser for executors.
  jsonRpcHandler({ requestHandler, userBuilder: keycardUserBuilder() }),
);

app.listen(3000);
```

### Call a remote A2A agent

```typescript
import { DelegationClient, getKeycardAuth } from "@keycardai/a2a";

const client = new DelegationClient(config);

// Inside your executor — pass the caller's token for delegation chain
async execute(requestContext, eventBus) {
  const auth = getKeycardAuth(requestContext)!;
  const result = await client.invokeService(
    "https://remote-agent.example.com",
    "Summarize this document",
    { subjectToken: auth.token },
  );
  eventBus.publish(result.message);
  eventBus.finished();
}
```

## How it works

Auth happens in two layers:

1. `requireBearerAuth` (from [`@keycardai/express`](../express/), re-exported here) fronts the JSON-RPC handler as standard Express middleware. It validates the bearer token with `TokenVerifier`, rejects auth failures with HTTP 401 and an RFC 6750 `WWW-Authenticate` challenge, and sets `req.auth` to the verified `AccessToken`.
2. `keycardUserBuilder` implements [`@a2a-js/sdk`'s `UserBuilder`](https://github.com/a2aproject/a2a-js) interface, the auth extension point of the SDK's Express handlers. It wraps the already-verified token from `req.auth` into a `KeycardUser` (no second verification) and injects it into each `RequestContext` via `ServerCallContext`. This is the same pattern as Python's `KeycardServerCallContextBuilder`.

If you skip the middleware and pass verification options directly to `keycardUserBuilder(options)`, it verifies the token itself, but auth failures then surface as JSON-RPC errors over HTTP 500 without a `WWW-Authenticate` challenge, because `@a2a-js/sdk`'s handlers convert thrown builder errors to 500. Prefer the middleware composition.

`getKeycardAuth(requestContext)` extracts that `AccessToken` in the executor, giving you the caller's identity and a ready-to-use `token` string for downstream RFC 8693 delegation.

## API

| Export | Description |
|---|---|
| `requireBearerAuth(options)` | Express middleware (re-exported from `@keycardai/express`); 401 + `WWW-Authenticate` on auth failure, sets `req.auth` |
| `keycardUserBuilder(options?)` | Returns a `UserBuilder` for `@a2a-js/sdk`'s Express handlers; wraps `req.auth` into a `KeycardUser`, or verifies the token itself when given options |
| `KeycardUser` | Implements `User`, carries `AccessToken` |
| `getKeycardAuth(requestContext)` | Extracts `AccessToken` from executor context; returns `null` if unauthenticated |
| `createKeycardRequestHandler(executor, agentCard, options?)` | Convenience wrapper creating `DefaultRequestHandler` with `InMemoryTaskStore` |
| `buildAgentCard(config)` | Builds an `AgentCard` from `AgentServiceConfig` |
| `DelegationClient` | Discovers, exchanges tokens, and invokes remote A2A agents |
| `ServiceDiscovery` | Fetches and caches agent cards from `/.well-known/agent-card.json` |
| `AgentServiceConfig` | Config: service name, credentials, identity URL, zone |

Re-exports from `@a2a-js/sdk`: `agentCardHandler`, `jsonRpcHandler`, `restHandler`, `UserBuilder`, `AgentExecutor`, `RequestContext`, `ExecutionEventBus`, `InMemoryTaskStore`, `DefaultRequestHandler`, `AgentCard`, `Message`, `Task`.

## Related Packages

- [`@keycardai/oauth`](../oauth/) — Token exchange primitives used by `DelegationClient`
- [`@keycardai/express`](../express/) — Bearer auth middleware for plain HTTP APIs
- [Keycard TypeScript SDK](../../README.md) — Root documentation
