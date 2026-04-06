/**
 * Pi-mono Coding Agent with Keycard MCP Tools
 *
 * A CLI agent powered by pi-mono that can access Keycard-protected MCP
 * servers (GitHub, Slack, Linear, etc.) through OAuth-authenticated tools.
 *
 * Prerequisites:
 *   1. A Keycard zone with an identity provider configured
 *   2. One or more MCP servers registered as resources in Keycard Console
 *   3. An Anthropic API key (or other supported provider)
 *
 * See README.md for full setup instructions.
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import {
  createAgentSession,
  SessionManager,
  AuthStorage,
  ModelRegistry,
} from "@mariozechner/pi-coding-agent";
import { PiMonoClient, ConsoleAuthToolHandler } from "@keycardai/pi-mono";

// ---------------------------------------------------------------------------
// Configuration — set these via environment variables
// ---------------------------------------------------------------------------

const MCP_SERVERS = [
  {
    name: "github",
    url: process.env.GITHUB_MCP_URL ?? "https://github-mcp.example.com/mcp",
  },
  // Add more servers:
  // { name: "slack", url: process.env.SLACK_MCP_URL ?? "https://slack-mcp.example.com/mcp" },
  // { name: "linear", url: process.env.LINEAR_MCP_URL ?? "https://linear-mcp.example.com/mcp" },
];

const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
if (!ANTHROPIC_API_KEY) {
  console.error("Set ANTHROPIC_API_KEY to run this agent.");
  process.exit(1);
}

// ---------------------------------------------------------------------------
// 1. Connect MCP clients to Keycard-protected servers
// ---------------------------------------------------------------------------

console.log("Connecting to MCP servers...");

const connectedServers = await Promise.all(
  MCP_SERVERS.map(async (server) => {
    const client = new Client({ name: "pi-mono-agent", version: "1.0.0" });
    try {
      const transport = new StreamableHTTPClientTransport(new URL(server.url));
      await client.connect(transport);
      console.log(`  Connected: ${server.name}`);
    } catch (error) {
      console.warn(`  Failed to connect to ${server.name}:`, error instanceof Error ? error.message : error);
    }
    return { name: server.name, client };
  }),
);

// ---------------------------------------------------------------------------
// 2. Create Keycard adapter and detect auth status
// ---------------------------------------------------------------------------

const keycardClient = new PiMonoClient({
  servers: connectedServers,
  authHandler: new ConsoleAuthToolHandler(),
  generateAuthUrl: async (serverName) => {
    // In a real app, you'd discover the authorization endpoint via
    // RFC 9728 metadata and build a PKCE auth URL. See the playthis-agent
    // example for a full implementation.
    return `https://your-zone.keycard.cloud/authorize?server=${serverName}`;
  },
});

await keycardClient.detectAuthStatus();

const authorized = keycardClient.getAuthorizedServers();
const unauthorized = keycardClient.getUnauthorizedServers();

console.log(`\nAuthorized: ${authorized.length > 0 ? authorized.join(", ") : "(none)"}`);
if (unauthorized.length > 0) {
  console.log(`Needs auth: ${unauthorized.join(", ")}`);
}

// ---------------------------------------------------------------------------
// 3. Get pi-mono tools and system prompt
// ---------------------------------------------------------------------------

const mcpTools = await keycardClient.getTools();
const authTools = await keycardClient.getAuthTools();
const systemPromptSection = keycardClient.getSystemPrompt();

console.log(`\nLoaded ${mcpTools.length} MCP tool(s), ${authTools.length} auth tool(s)`);

// ---------------------------------------------------------------------------
// 4. Create pi-mono agent session
// ---------------------------------------------------------------------------

const authStorage = AuthStorage.create();
authStorage.setRuntimeApiKey("anthropic", ANTHROPIC_API_KEY);
const modelRegistry = ModelRegistry.create(authStorage);

const { session } = await createAgentSession({
  sessionManager: SessionManager.inMemory(),
  authStorage,
  modelRegistry,
  tools: [...mcpTools, ...authTools],
  systemPrompt: `You are a helpful coding assistant.\n\n${systemPromptSection}`,
});

// ---------------------------------------------------------------------------
// 5. Run a prompt and stream the response
// ---------------------------------------------------------------------------

console.log("\n--- Agent Response ---\n");

session.subscribe((event: Record<string, unknown>) => {
  if (
    event.type === "message_update" &&
    typeof event.assistantMessageEvent === "object" &&
    event.assistantMessageEvent !== null
  ) {
    const ame = event.assistantMessageEvent as Record<string, unknown>;
    if (ame.type === "text_delta" && typeof ame.delta === "string") {
      process.stdout.write(ame.delta);
    }
  }
});

// Use the first argument as the prompt, or a default
const prompt = process.argv[2] ?? "What tools do you have available? List them briefly.";
await session.prompt(prompt);

console.log("\n");

// Cleanup
for (const server of connectedServers) {
  await server.client.close().catch(() => {});
}
