# @keycardai/a2a

> **Preview.** This SDK has not reached parity with the Keycard Python SDK. APIs may change between minor versions.

Keycard auth integration for the [Agent-to-Agent (A2A) protocol](https://google.github.io/A2A). Build authenticated A2A agent servers and clients with Keycard-issued bearer tokens.

**No external A2A SDK dependency** — implements the A2A JSONRPC protocol directly. Python equivalent: [`keycardai-a2a`](https://github.com/keycardai/python-sdk/tree/main/packages/a2a).

## Installation

```bash
npm install @keycardai/a2a express
```

## Quick Start

### Build an A2A agent server

```typescript
import express from "express";
import { createAgentRouter, AgentExecutor } from "@keycardai/a2a";

const executor: AgentExecutor = {
  async execute(message, context) {
    // context.auth is the verified AccessToken
    // context.accessToken is the raw bearer string for downstream delegation
    const text = message.parts[0].type === "text" ? message.parts[0].text : "";
    return {
      messageId: crypto.randomUUID(),
      role: "agent",
      parts: [{ type: "text", text: `Hello: ${text}` }],
    };
  },
};

const config = {
  serviceName: "My Agent",
  clientId: process.env.KEYCARD_CLIENT_ID!,
  clientSecret: process.env.KEYCARD_CLIENT_SECRET!,
  identityUrl: "https://my-agent.example.com",
  zoneId: process.env.KEYCARD_ZONE_ID,
};

const app = express();
app.use(express.json());
app.use(createAgentRouter(executor, config, {
  issuer: `https://${config.zoneId}.keycard.cloud`,
}));

app.listen(3000);
```

`createAgentRouter` mounts:
- `GET /.well-known/agent-card.json` — serves agent metadata
- `POST /a2a/jsonrpc` — Keycard-authenticated, dispatches to `executor.execute()`

### Call a remote A2A agent

```typescript
import { DelegationClient } from "@keycardai/a2a";

const client = new DelegationClient({
  serviceName: "My Service",
  clientId: process.env.KEYCARD_CLIENT_ID!,
  clientSecret: process.env.KEYCARD_CLIENT_SECRET!,
  identityUrl: "https://my-service.example.com",
  zoneId: process.env.KEYCARD_ZONE_ID,
});

// Inside a request handler — pass the caller's token for delegation chain
const result = await client.invokeService(
  "https://remote-agent.example.com",
  "What is the weather today?",
  { subjectToken: context.accessToken },
);
console.log(result.message.parts[0].text);
```

### Discover remote agents

```typescript
import { ServiceDiscovery } from "@keycardai/a2a";

const discovery = new ServiceDiscovery();
const card = await discovery.getServiceCard("https://remote-agent.example.com");
console.log(card.name, card.skills);
```

## API

| Export | Description |
|---|---|
| `createAgentRouter(executor, config, options)` | Express Router with `/.well-known/agent-card.json` and `/a2a/jsonrpc` |
| `AgentExecutor` (interface) | Implement to handle incoming A2A tasks |
| `AgentExecutorContext` | Context passed to executor: `auth: AccessToken`, `accessToken: string` |
| `DelegationClient` | Client for calling remote A2A agents with Keycard delegation |
| `ServiceDiscovery` | Fetches and caches agent cards from `/.well-known/agent-card.json` |
| `AgentServiceConfig` | Config bag: service identity, credentials, agent card metadata |
| `AgentCard`, `A2AMessage`, `Part` | A2A protocol types |

## Related Packages

- [`@keycardai/express`](../express/) — bearer auth middleware used by the agent server
- [`@keycardai/oauth`](../oauth/) — token exchange primitives used by the delegation client
- [Keycard TypeScript SDK](../../README.md) — root documentation
