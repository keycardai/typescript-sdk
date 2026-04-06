# @keycardai/pi-mono

[Pi-mono](https://github.com/badlogic/pi-mono) agent integration for Keycard — converts MCP tools from Keycard-protected servers into pi-mono `AgentTool` instances with OAuth auth handling and auth-aware system prompts.

This is a **client-side** integration. If you're building an MCP server, you want [`@keycardai/mcp`](../mcp/) instead.

## Installation

```bash
npm install @keycardai/pi-mono @mariozechner/pi-agent-core @mariozechner/pi-ai @modelcontextprotocol/sdk @sinclair/typebox
```

## Quick Start

```typescript
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { PiMonoClient } from "@keycardai/pi-mono";
import {
  createAgentSession,
  SessionManager,
  AuthStorage,
  ModelRegistry,
} from "@mariozechner/pi-coding-agent";

// 1. Connect MCP clients to your Keycard-protected servers
const githubClient = new Client({ name: "my-app", version: "1.0" });
await githubClient.connect(
  new StreamableHTTPClientTransport(new URL("https://github-mcp.example.com/mcp")),
);

// 2. Create the Keycard adapter
const adapter = new PiMonoClient({
  servers: [{ name: "github", client: githubClient }],
});
await adapter.detectAuthStatus();

// 3. Get pi-mono native tools and system prompt
const tools = await adapter.getTools();
const authTools = await adapter.getAuthTools();
const systemPrompt = adapter.getSystemPrompt("You are a helpful assistant.");

// 4. Create a pi-mono agent session
const authStorage = AuthStorage.create();
const modelRegistry = ModelRegistry.create(authStorage);

const { session } = await createAgentSession({
  sessionManager: SessionManager.inMemory(),
  authStorage,
  modelRegistry,
  tools: [...tools, ...authTools],
  systemPrompt,
});

// 5. Use the agent — it can now call Keycard-protected MCP tools
session.subscribe((event) => {
  if (event.type === "message_update" && event.assistantMessageEvent.type === "text_delta") {
    process.stdout.write(event.assistantMessageEvent.delta);
  }
});

await session.prompt("List my open PRs on GitHub");
```

## How It Works

Pi-mono agents accept tools as `AgentTool[]` arrays. This package bridges Keycard-protected MCP servers into that model:

1. **Auth detection** — `detectAuthStatus()` probes each MCP server by calling `listTools()`. Servers that respond are marked authorized; servers that reject are marked unauthorized.

2. **Tool conversion** — `getTools()` converts MCP tools into pi-mono `AgentTool` instances. JSON Schema parameters are bridged to TypeBox via `Type.Unsafe()`. Each tool's `execute()` proxies to `client.callTool()` on the MCP server.

3. **Auth tools** — `getAuthTools()` returns a `request_authorization` tool the agent can call to trigger OAuth flows for unauthorized servers. Auth link delivery is handled by a pluggable `AuthToolHandler`.

4. **System prompt** — `getSystemPrompt()` generates a section listing which servers are authorized and which need auth, with instructions for the agent.

All pi-mono framework features (extensions, skills, AGENTS.md discovery, session management, compaction, thinking levels) work unchanged — Keycard tools are just additional entries in the agent's toolkit.

## API

### `PiMonoClient`

```typescript
import { PiMonoClient } from "@keycardai/pi-mono";

const adapter = new PiMonoClient({
  // Connected MCP Client instances
  servers: [{ name: "github", client: githubMcpClient }],

  // Optional: custom auth link handler (default: returns URL string)
  authHandler: new ConsoleAuthToolHandler(),

  // Optional: generates OAuth URLs when agent requests authorization
  generateAuthUrl: async (serverName) => "https://auth.example.com/...",
});
```

| Method | Returns | Description |
|---|---|---|
| `detectAuthStatus()` | `Promise<void>` | Probes servers and sets auth status |
| `getTools()` | `Promise<AgentTool[]>` | MCP tools as pi-mono AgentTools (authorized servers only) |
| `getAuthTools()` | `Promise<AgentTool[]>` | Auth request tool (if servers need authorization) |
| `getSystemPrompt(base?)` | `string` | Auth-aware system prompt section |
| `getAuthorizedServers()` | `string[]` | Names of authorized servers |
| `getUnauthorizedServers()` | `string[]` | Names of servers needing auth |
| `getServerStates()` | `ReadonlyMap` | Full state map for all servers |
| `clearCache()` | `void` | Forces tool re-fetch on next `getTools()` |

### `AuthToolHandler`

Pluggable interface for delivering OAuth links to users:

```typescript
import { DefaultAuthToolHandler, ConsoleAuthToolHandler } from "@keycardai/pi-mono";

// Default: returns URL string for the agent to display
const handler = new DefaultAuthToolHandler();

// Console: prints URL to stdout (for CLI apps)
const handler = new ConsoleAuthToolHandler();

// Custom: implement the interface
const handler: AuthToolHandler = {
  async handleAuthRequest(serverName, authUrl, reason?) {
    // Post to Slack, render in web UI, etc.
    return "Authorization link sent!";
  },
};
```

### Tool Conversion Utilities

For advanced use cases, the conversion functions are exported directly:

```typescript
import { convertMcpToolToAgentTool, convertServerTools, jsonSchemaToTypeBox } from "@keycardai/pi-mono";

// Convert a single MCP tool
const agentTool = convertMcpToolToAgentTool(mcpTool, "github", mcpClient);

// Convert all tools from a server
const tools = await convertServerTools("github", mcpClient);
```

## Tool Naming

Tools are prefixed with the server name to avoid collisions across servers:

- `github__list_repos`
- `slack__send_message`
- `linear__create_issue`
