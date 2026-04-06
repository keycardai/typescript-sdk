/**
 * @keycardai/pi-mono — Pi-mono (coding agent) integration for Keycard.
 *
 * Converts MCP tools from Keycard-protected servers into pi-mono AgentTool
 * instances with OAuth auth handling and auth-aware system prompts.
 *
 * @example
 * ```typescript
 * import { PiMonoClient } from "@keycardai/pi-mono";
 * import { createAgentSession, SessionManager } from "@mariozechner/pi-coding-agent"; // or pi-agent-core
 *
 * const adapter = new PiMonoClient({
 *   servers: [{ name: "github", client: githubMcpClient }],
 * });
 * await adapter.detectAuthStatus();
 *
 * const tools = await adapter.getTools();
 * const authTools = await adapter.getAuthTools();
 * const prompt = adapter.getSystemPrompt("You are a helpful assistant.");
 *
 * const { session } = await createAgentSession({
 *   tools: [...tools, ...authTools],
 *   systemPrompt: prompt,
 *   sessionManager: SessionManager.inMemory(),
 * });
 * ```
 */

// Main client
export { PiMonoClient } from "./client.js";
export type { ConnectedServer, PiMonoClientConfig } from "./client.js";

// Auth tool handlers
export { DefaultAuthToolHandler, ConsoleAuthToolHandler, createAuthRequestTool } from "./auth-tools.js";

// Tool conversion utilities
export { convertMcpToolToAgentTool, convertServerTools, jsonSchemaToTypeBox } from "./tools.js";

// Prompt builder
export { buildSystemPromptSection } from "./prompt.js";

// Types
export type {
  ServerAuthStatus,
  ServerState,
  AuthToolHandler,
} from "./types.js";
