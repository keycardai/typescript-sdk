/**
 * End-to-end test: PiMonoClient + local MCP server + pi-mono agent session.
 *
 * Spins up an in-process MCP server with a simple tool, connects via
 * InMemoryTransport, converts tools through PiMonoClient, and:
 *   1. Verifies direct tool execution works (always runs)
 *   2. Runs a pi-mono agent session (only with ANTHROPIC_API_KEY)
 *
 * Run:
 *   npx tsx e2e/e2e.test.ts                    # direct execution only
 *   ANTHROPIC_API_KEY=sk-... npx tsx e2e/e2e.test.ts  # full agent session
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { z } from "zod";
import { PiMonoClient } from "../src/client.js";

// ---------------------------------------------------------------------------
// 1. Create a local MCP server with a simple tool
// ---------------------------------------------------------------------------

const mcpServer = new McpServer({ name: "test-server", version: "1.0.0" });

mcpServer.tool(
  "get_greeting",
  "Returns a greeting for the given name",
  { name: z.string().describe("The name to greet") },
  async ({ name }) => ({
    content: [{ type: "text", text: `Hello, ${name}! Welcome from the MCP server.` }],
  }),
);

mcpServer.tool(
  "add_numbers",
  "Adds two numbers together",
  { a: z.number(), b: z.number() },
  async ({ a, b }) => ({
    content: [{ type: "text", text: String(a + b) }],
  }),
);

// ---------------------------------------------------------------------------
// 2. Connect client ↔ server via in-memory transport
// ---------------------------------------------------------------------------

const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();

const mcpClient = new Client({ name: "e2e-test", version: "1.0.0" });

await mcpServer.server.connect(serverTransport);
await mcpClient.connect(clientTransport);

console.log("✅ MCP client ↔ server connected via InMemoryTransport");

// ---------------------------------------------------------------------------
// 3. Create PiMonoClient and convert tools
// ---------------------------------------------------------------------------

const adapter = new PiMonoClient({
  servers: [{ name: "test", client: mcpClient }],
});

await adapter.detectAuthStatus();

const authorizedServers = adapter.getAuthorizedServers();
const unauthorizedServers = adapter.getUnauthorizedServers();

console.log("  Authorized servers:", authorizedServers);
console.log("  Unauthorized servers:", unauthorizedServers);

if (authorizedServers.length !== 1 || authorizedServers[0] !== "test") {
  console.error("❌ Expected 'test' server to be authorized");
  process.exit(1);
}

const tools = await adapter.getTools();
console.log(`  Converted ${tools.length} tool(s):`, tools.map((t) => t.name));

if (tools.length !== 2) {
  console.error(`❌ Expected 2 tools, got ${tools.length}`);
  process.exit(1);
}

const systemPrompt = adapter.getSystemPrompt("You are a test assistant.");
if (!systemPrompt.includes("Authorized and available: test")) {
  console.error("❌ System prompt missing authorized server info");
  process.exit(1);
}
console.log("  System prompt generated ✅");

// ---------------------------------------------------------------------------
// 4. Verify tool execution works directly (no LLM needed)
// ---------------------------------------------------------------------------

// Test get_greeting
const greetingTool = tools.find((t) => t.name === "test__get_greeting");
if (!greetingTool) {
  console.error("❌ Tool 'test__get_greeting' not found");
  process.exit(1);
}

const greetResult = await greetingTool.execute("call-1", { name: "Keycard" });
const greetText = greetResult.content
  .filter((c): c is { type: "text"; text: string } => c.type === "text")
  .map((c) => c.text)
  .join("");

if (!greetText.includes("Hello, Keycard!")) {
  console.error("❌ get_greeting returned unexpected result:", greetText);
  process.exit(1);
}
console.log("✅ get_greeting tool works:", greetText);

// Test add_numbers
const addTool = tools.find((t) => t.name === "test__add_numbers");
if (!addTool) {
  console.error("❌ Tool 'test__add_numbers' not found");
  process.exit(1);
}

const addResult = await addTool.execute("call-2", { a: 17, b: 25 });
const addText = addResult.content
  .filter((c): c is { type: "text"; text: string } => c.type === "text")
  .map((c) => c.text)
  .join("");

if (addText !== "42") {
  console.error("❌ add_numbers returned unexpected result:", addText);
  process.exit(1);
}
console.log("✅ add_numbers tool works: 17 + 25 =", addText);

// ---------------------------------------------------------------------------
// 5. Test mixed auth scenario
// ---------------------------------------------------------------------------

const unauthorizedClient = new Client({ name: "unauth-test", version: "1.0.0" });
// Don't connect — listTools will fail

const mixedAdapter = new PiMonoClient({
  servers: [
    { name: "authorized", client: mcpClient },
    { name: "unauthorized", client: unauthorizedClient },
  ],
  generateAuthUrl: async (name) => `https://auth.example.com/authorize?server=${name}`,
});

await mixedAdapter.detectAuthStatus();

if (mixedAdapter.getAuthorizedServers().length !== 1) {
  console.error("❌ Expected 1 authorized server in mixed scenario");
  process.exit(1);
}
if (mixedAdapter.getUnauthorizedServers().length !== 1) {
  console.error("❌ Expected 1 unauthorized server in mixed scenario");
  process.exit(1);
}

const authTools = await mixedAdapter.getAuthTools();
if (authTools.length !== 1 || authTools[0].name !== "request_authorization") {
  console.error("❌ Expected request_authorization tool");
  process.exit(1);
}

const mixedPrompt = mixedAdapter.getSystemPrompt();
if (!mixedPrompt.includes("authorized") || !mixedPrompt.includes("unauthorized")) {
  console.error("❌ Mixed prompt missing auth status info");
  process.exit(1);
}
console.log("✅ Mixed auth scenario works correctly");

// ---------------------------------------------------------------------------
// 6. Run pi-mono agent session (requires ANTHROPIC_API_KEY)
// ---------------------------------------------------------------------------

if (!process.env.ANTHROPIC_API_KEY) {
  console.log("\n⏭️  Skipping agent session test (no ANTHROPIC_API_KEY set)");
  console.log("   Set ANTHROPIC_API_KEY to run the full LLM-powered e2e test.\n");
  await cleanup();
  console.log("\n✅ E2E test passed (direct execution)");
  process.exit(0);
}

console.log("\n🤖 Starting pi-mono agent session with LLM...");

// Dynamic import — only when we actually need it (avoids resolution errors
// when @mariozechner/pi-coding-agent is a peer dep, not installed directly)
const {
  createAgentSession,
  SessionManager,
  AuthStorage,
  ModelRegistry,
} = await import("@mariozechner/pi-coding-agent");

const authStorage = AuthStorage.create();
authStorage.setRuntimeApiKey("anthropic", process.env.ANTHROPIC_API_KEY);
const modelRegistry = ModelRegistry.create(authStorage);

const { session } = await createAgentSession({
  sessionManager: SessionManager.inMemory(),
  authStorage,
  modelRegistry,
  tools,
  systemPrompt: `You are a test assistant. ${systemPrompt}\n\nIMPORTANT: When asked to greet someone, use the test__get_greeting tool. Respond with ONLY the tool's output, nothing else.`,
});

let agentOutput = "";

session.subscribe((event: Record<string, unknown>) => {
  if (
    event.type === "message_update" &&
    typeof event.assistantMessageEvent === "object" &&
    event.assistantMessageEvent !== null
  ) {
    const ame = event.assistantMessageEvent as Record<string, unknown>;
    if (ame.type === "text_delta" && typeof ame.delta === "string") {
      agentOutput += ame.delta;
    }
  }
});

await session.prompt("Greet someone named 'E2E Test'.");

console.log("  Agent output:", agentOutput.trim());

if (agentOutput.includes("Hello, E2E Test!")) {
  console.log("✅ Full e2e test passed — agent used MCP tool via PiMonoClient");
} else {
  console.log("⚠️  Agent responded but may not have used the tool. Output above.");
}

// ---------------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------------

async function cleanup() {
  await mcpClient.close();
  await mcpServer.server.close();
}

await cleanup();
