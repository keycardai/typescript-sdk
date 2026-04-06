# Pi-mono Agent with Keycard MCP Tools

A CLI coding agent powered by [pi-mono](https://github.com/badlogic/pi-mono) that can access Keycard-protected MCP servers (GitHub, Slack, Linear, etc.) through OAuth-authenticated tools. Demonstrates `@keycardai/pi-mono` — the pi-mono integration for the Keycard TypeScript SDK.

## What This Example Shows

- Connecting to Keycard-protected MCP servers via `@modelcontextprotocol/sdk`
- Using `PiMonoClient` to convert MCP tools into pi-mono `AgentTool` instances
- Auth-aware system prompt generation (authorized vs unauthorized servers)
- Console-based OAuth flow for unauthorized servers
- Creating a `createAgentSession()` with Keycard tools

## Prerequisites

- **Node.js 18+**
- **Anthropic API key** (or another provider supported by pi-mono)
- **Keycard account** — sign up at [console.keycard.ai](https://console.keycard.ai)
- **Configured zone** with an identity provider (Okta, Auth0, Google, etc.)
- **At least one MCP server** registered as a resource in Keycard Console

## Keycard Console Setup

### 1. Register Your MCP Server as a Resource

If you have a Keycard-protected MCP server running (see the [Cloudflare Worker](../cloudflare-worker/) or [Hello World](../hello-world-server/) examples):

1. Navigate to **Resources** → **Create Resource**
2. Configure:
   - **Resource Name:** `GitHub MCP Server`
   - **Resource Identifier:** `https://your-mcp-server.example.com`
   - **Credential Provider:** Zone Provider
   - **Scopes:** `mcp:tools`

### 2. Create Application Credentials

1. Navigate to **Applications** → **Create Application**
2. Note the **Client ID** and **Client Secret** — you'll need these for the OAuth flow

## Install and Run

```bash
cd examples/pi-mono-agent
npm install
```

Set your API key and MCP server URL:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
export GITHUB_MCP_URL=https://your-mcp-server.example.com/mcp
```

Run the agent:

```bash
npm start
```

Or with a custom prompt:

```bash
npm start -- "List my open pull requests on GitHub"
```

## How It Works

```
┌──────────────┐     ┌───────────────┐     ┌──────────────┐
│  pi-mono     │────▶│ PiMonoClient  │────▶│ MCP Server   │
│  Agent       │     │ (Keycard SDK) │     │ (Keycard     │
│  Session     │     │               │     │  protected)  │
│              │◀────│ AgentTool[]   │◀────│              │
└──────────────┘     └───────────────┘     └──────────────┘
       │                                          │
       │  prompt("List my PRs")                   │
       │  ──▶ calls github__list_pulls            │
       │       ──▶ MCP callTool()  ──────────────▶│
       │       ◀── result          ◀──────────────│
       │  ◀── "You have 3 open PRs..."            │
```

1. **Connect** — MCP clients connect to Keycard-protected servers
2. **Detect auth** — `PiMonoClient` probes each server; authorized ones get their tools converted
3. **Convert tools** — MCP tools become pi-mono `AgentTool` instances (JSON Schema → TypeBox)
4. **Create session** — `createAgentSession()` with the converted tools + auth tools
5. **Prompt** — The LLM sees the tools, calls them as needed, results flow back through MCP

## Configuration

Edit the `MCP_SERVERS` array in `src/index.ts` to add your servers:

```typescript
const MCP_SERVERS = [
  { name: "github", url: process.env.GITHUB_MCP_URL ?? "https://..." },
  { name: "slack",  url: process.env.SLACK_MCP_URL  ?? "https://..." },
  { name: "linear", url: process.env.LINEAR_MCP_URL ?? "https://..." },
];
```

## Environment Variables

| Variable | Description |
|---|---|
| `ANTHROPIC_API_KEY` | Anthropic API key (required) |
| `GITHUB_MCP_URL` | URL of your GitHub MCP server |
| `SLACK_MCP_URL` | URL of your Slack MCP server |
| `LINEAR_MCP_URL` | URL of your Linear MCP server |

## Related

- [`@keycardai/pi-mono` docs](https://docs.keycard.ai/sdk/pi-mono/) — full API reference
- [Cloudflare Worker example](../cloudflare-worker/) — build the MCP server this agent connects to
- [Hello World example](../hello-world-server/) — Express-based MCP server
- [pi-mono SDK docs](https://github.com/badlogic/pi-mono/blob/main/packages/coding-agent/docs/sdk.md) — pi-mono framework reference
