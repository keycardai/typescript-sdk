# @keycardai/a2a

Keycard auth integration for the [Agent-to-Agent (A2A) protocol](https://google.github.io/A2A). Wraps [`@a2a-js/sdk`](https://github.com/a2aproject/a2a-js) the same way Python's `keycardai-a2a` wraps `a2a-sdk 1.x` — adds Keycard auth on top of the existing SDK's routing, executor, and task store infrastructure.

Python equivalent: [`keycardai-a2a`](https://github.com/keycardai/python-sdk/tree/main/packages/a2a).

## Installation

```bash
npm install @keycardai/a2a @a2a-js/sdk express
```

Requires `@a2a-js/sdk` 1.x (A2A protocol 1.0). See [Protocol version and 0.3 agents](#protocol-version-and-03-agents) for interop with agents still on 0.3.

## Quick Start

### Build an A2A agent server

```typescript
import express from "express";
import { agentCardHandler, jsonRpcHandler } from "@a2a-js/sdk/server/express";
import { InMemoryTaskStore, type AgentExecutor, type RequestContext, type ExecutionEventBus } from "@a2a-js/sdk/server";
import { Role } from "@a2a-js/sdk";
import {
  requireBearerAuth,
  keycardMetadataRouter,
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
    const part = requestContext.userMessage.parts[0]?.content;
    const text = part?.$case === "text" ? part.value : "";
    eventBus.publish({
      kind: "message",
      data: {
        messageId: crypto.randomUUID(),
        contextId: "",
        taskId: "",
        role: Role.ROLE_AGENT,
        parts: [{ content: { $case: "text", value: `Hello: ${text}` }, metadata: undefined, filename: "", mediaType: "" }],
        metadata: undefined,
        extensions: [],
        referenceTaskIds: [],
      },
    });
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
// Serves /.well-known/oauth-protected-resource (RFC 9728). This is what makes
// the resource_metadata URL in requireBearerAuth's 401 challenge resolve.
app.use(keycardMetadataRouter({ issuer: `https://${config.zoneId}.keycard.cloud` }));
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
  // A 1.0 agent answers SendMessage with either a message or a task.
  if (result.message) eventBus.publish({ kind: "message", data: result.message });
  else if (result.task) eventBus.publish({ kind: "task", data: result.task });
  eventBus.finished();
}
```

## Protocol version and 0.3 agents

This package speaks A2A protocol 1.0: `DelegationClient` sends the `SendMessage` JSON-RPC method with an `A2A-Version: 1.0` header, and `buildAgentCard` advertises a 1.0 JSON-RPC interface under `supportedInterfaces`. That is what `keycardai-a2a` (Python, `a2a-sdk` 1.x) serves and sends, so the two interoperate out of the box.

Agents built on the 0.3 generation (`@keycardai/a2a` 0.3.x, or the Go and Ruby integrations until they move) do not interoperate by default: their cards have no 1.0 interface, and they answer `SendMessage` with `-32601 MethodNotFound`. `@a2a-js/sdk` ships an opt-in compatibility layer for the migration window, and this package passes it through rather than translating envelopes itself:

```typescript
// Client side: talk 0.3 to agents whose card only advertises 0.3.
// The wire generation is chosen per agent from its card; 1.0 agents still get 1.0.
const client = new DelegationClient(config, { legacyCompat: { enabled: true } });

// Server side: also accept 0.3 envelopes (message/send) from old callers.
const agentCard = buildAgentCard(config, { legacyCompat: { enabled: true } });
app.use("/.well-known/agent-card.json", agentCardHandler({ agentCardProvider: requestHandler, legacyCompat: { enabled: true } }));
app.use("/a2a/jsonrpc", requireBearerAuth({ ... }), jsonRpcHandler({ requestHandler, userBuilder: keycardUserBuilder(), legacyCompat: { enabled: true } }));
```

The Python equivalent is `enable_v0_3_compat` in `keycardai-a2a`. See the upstream [v0.3 compatibility guide](https://github.com/a2aproject/a2a-js/blob/main/docs/compatibility-v0_3.md).

## How it works

Auth happens in two layers:

1. `requireBearerAuth` (from [`@keycardai/express`](../express/), re-exported here) fronts the JSON-RPC handler as standard Express middleware. It validates the bearer token with `TokenVerifier`, rejects auth failures with HTTP 401 and an RFC 6750 `WWW-Authenticate` challenge, sets `req.auth` to the verified `AccessToken`, and brands the request with a provenance symbol. The 401 challenge advertises a `resource_metadata` URL (RFC 9728); `keycardMetadataRouter`, mounted at the app root, is what serves that URL.
2. `keycardUserBuilder` implements [`@a2a-js/sdk`'s `UserBuilder`](https://github.com/a2aproject/a2a-js) interface, the auth extension point of the SDK's Express handlers. It wraps the already-verified token from the branded request into a `KeycardUser` (no second verification) and injects it into each `RequestContext` via `ServerCallContext`. It deliberately ignores bare `req.auth`, which other middleware such as express-jwt also populates. This is the same pattern as Python's `KeycardServerCallContextBuilder`.

If you skip the middleware and pass verification options directly to `keycardUserBuilder(options)`, it verifies the token itself, but auth failures then surface as JSON-RPC errors over HTTP 500 without a `WWW-Authenticate` challenge, because `@a2a-js/sdk`'s handlers convert thrown builder errors to 500. Prefer the middleware composition.

`getKeycardAuth(requestContext)` extracts that `AccessToken` in the executor, giving you the caller's identity and a ready-to-use `token` string for downstream RFC 8693 delegation.

## API

| Export | Description |
|---|---|
| `requireBearerAuth(options)` | Express middleware (re-exported from `@keycardai/express`); 401 + `WWW-Authenticate` on auth failure, sets `req.auth` |
| `keycardMetadataRouter(options)` | Express router (re-exported from `@keycardai/express`) serving the RFC 9728/8414 discovery endpoints that the 401 challenge's `resource_metadata` URL points at |
| `keycardUserBuilder(options?)` | Returns a `UserBuilder` for `@a2a-js/sdk`'s Express handlers; wraps `req.auth` into a `KeycardUser`, or verifies the token itself when given options |
| `KeycardUser` | Implements `User`, carries `AccessToken` |
| `getKeycardAuth(requestContext)` | Extracts `AccessToken` from executor context; returns `null` if unauthenticated |
| `createKeycardRequestHandler(executor, agentCard, options?)` | Convenience wrapper creating `DefaultRequestHandler` with `InMemoryTaskStore` |
| `buildAgentCard(config, options?)` | Builds a 1.0 `AgentCard` from `AgentServiceConfig`; `options.legacyCompat` also advertises a 0.3 interface |
| `DelegationClient` | Discovers, exchanges tokens, and invokes remote A2A agents over A2A 1.0; `options.legacyCompat` enables upstream's 0.3 client shim |
| `DelegationResult` | `{ message?, task?, agentCard }`: a 1.0 agent answers with a message or a task |
| `ServiceDiscovery` | Fetches and caches agent cards from `/.well-known/agent-card.json` |
| `AgentServiceConfig` | Config: service name, credentials, identity URL, zone |

Re-exports from `@a2a-js/sdk`: `agentCardHandler`, `jsonRpcHandler`, `restHandler`, `UserBuilder`, `AgentExecutor`, `RequestContext`, `ExecutionEventBus`, `InMemoryTaskStore`, `DefaultRequestHandler`, `AgentCard`, `Message`, `Task`, `Part`, `Role`, `A2A_PROTOCOL_VERSION`, `A2A_VERSION_HEADER`.

## Related Packages

- [`@keycardai/oauth`](../oauth/) — Token exchange primitives used by `DelegationClient`
- [`@keycardai/express`](../express/) — Bearer auth middleware for plain HTTP APIs
- [Keycard TypeScript SDK](../../README.md) — Root documentation
