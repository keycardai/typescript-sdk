/**
 * PiMonoClient — main adapter for using Keycard-protected MCP servers
 * with the pi-mono coding agent framework.
 *
 * Manages MCP server connections, converts tools to pi-mono AgentTool format,
 * handles OAuth auth status, and generates auth-aware system prompts.
 */

import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import type { AgentTool } from "@mariozechner/pi-agent-core";
import type {
  ServerState,
  AuthToolHandler,
} from "./types.js";
import { convertServerTools } from "./tools.js";
import { DefaultAuthToolHandler, createAuthRequestTool } from "./auth-tools.js";
import { buildSystemPromptSection } from "./prompt.js";

// ---------------------------------------------------------------------------
// Server connection descriptor
// ---------------------------------------------------------------------------

/**
 * A connected MCP server with its client instance.
 * Users create these by setting up MCP Client + Transport themselves,
 * then pass them to PiMonoClient.
 */
export interface ConnectedServer {
  /** Unique name for this server (used as tool prefix). */
  name: string;
  /** The connected MCP Client instance. */
  client: Client;
}

/** Options for creating a PiMonoClient. */
export interface PiMonoClientConfig {
  /**
   * List of Keycard-protected MCP servers to configure.
   * These are server descriptors — not yet connected.
   * The client will attempt to list tools from each to detect auth status.
   */
  servers: ConnectedServer[];

  /**
   * Pluggable handler for delivering OAuth authorization links to the user.
   * Defaults to DefaultAuthToolHandler (returns URL string for agent to display).
   */
  authHandler?: AuthToolHandler;

  /**
   * Function to generate an OAuth authorization URL for a server.
   * Called when the agent invokes the request_authorization tool.
   *
   * This is application-specific — you'll typically discover the server's
   * authorization endpoint and build a PKCE auth URL.
   */
  generateAuthUrl?: (serverName: string) => Promise<string>;
}

/**
 * PiMonoClient — adapter for using Keycard-protected MCP servers
 * with pi-mono's coding agent.
 *
 * Usage:
 * ```typescript
 * // 1. Set up MCP clients for each server (with Keycard OAuth transports)
 * const githubClient = new Client({ name: "github", version: "1.0" });
 * await githubClient.connect(githubTransport);
 *
 * // 2. Create the adapter
 * const adapter = new PiMonoClient({
 *   servers: [{ name: "github", client: githubClient }],
 * });
 *
 * // 3. Detect auth status
 * await adapter.detectAuthStatus();
 *
 * // 4. Get pi-mono tools and system prompt
 * const tools = await adapter.getTools();
 * const authTools = await adapter.getAuthTools();
 * const prompt = adapter.getSystemPrompt("You are a helpful assistant.");
 * ```
 */
export class PiMonoClient {
  readonly #servers: ConnectedServer[];
  readonly #authHandler: AuthToolHandler;
  readonly #generateAuthUrl?: (serverName: string) => Promise<string>;

  #serverStates: Map<string, ServerState> = new Map();
  #toolsCache: AgentTool[] | undefined;

  constructor(config: PiMonoClientConfig) {
    this.#servers = config.servers;
    this.#authHandler = config.authHandler ?? new DefaultAuthToolHandler();
    this.#generateAuthUrl = config.generateAuthUrl;
  }

  /**
   * Detect auth status of each server by attempting to list tools.
   *
   * Servers that respond successfully are marked "authorized".
   * Servers that throw (auth required, network error, etc.) are marked accordingly.
   *
   * Call this after connecting your MCP clients but before calling getTools().
   */
  async detectAuthStatus(): Promise<void> {
    this.#serverStates.clear();
    this.#toolsCache = undefined;

    const results = await Promise.allSettled(
      this.#servers.map(async (server) => {
        try {
          // Attempt to list tools — this will fail if not authorized
          await server.client.listTools();
          return { server, status: "authorized" as const, error: undefined };
        } catch (error) {
          return {
            server,
            status: "unauthorized" as const,
            error: error instanceof Error ? error.message : String(error),
          };
        }
      }),
    );

    for (const result of results) {
      if (result.status === "fulfilled") {
        const { server, status, error } = result.value;
        this.#serverStates.set(server.name, {
          name: server.name,
          status,
          client: status === "authorized" ? server.client : undefined,
          error,
        });
      } else {
        // Promise.allSettled rejected — shouldn't happen but handle gracefully
        console.error("Unexpected server detection failure:", result.reason);
      }
    }
  }

  /**
   * Get MCP tools converted to pi-mono AgentTool[] format.
   *
   * Only returns tools from authorized servers. Tools are prefixed with the
   * server name (e.g., "github__list_repos") to avoid naming collisions.
   *
   * Results are cached — call detectAuthStatus() again to refresh.
   */
  async getTools(): Promise<AgentTool[]> {
    if (this.#toolsCache) {
      return this.#toolsCache;
    }

    const tools: AgentTool[] = [];

    for (const [name, state] of this.#serverStates) {
      if (state.status !== "authorized" || !state.client) continue;

      try {
        const serverTools = await convertServerTools(name, state.client);
        tools.push(...serverTools);
      } catch (error) {
        console.error(`Failed to list tools for ${name}:`, error);
      }
    }

    this.#toolsCache = tools;
    return tools;
  }

  /**
   * Get auth request tools for unauthorized servers.
   *
   * Returns a single "request_authorization" AgentTool if any servers
   * need authorization. The agent can call this to trigger OAuth flows.
   *
   * Returns an empty array if all servers are authorized or if no
   * generateAuthUrl function was provided.
   */
  async getAuthTools(): Promise<AgentTool[]> {
    const unauthorized = this.getUnauthorizedServers();
    if (unauthorized.length === 0 || !this.#generateAuthUrl) {
      return [];
    }

    return [
      createAuthRequestTool(
        unauthorized,
        this.#authHandler,
        this.#generateAuthUrl,
      ),
    ];
  }

  /**
   * Generate an auth-aware system prompt section.
   *
   * Lists which servers are authorized and available, and which need
   * authorization. Instructs the agent to use request_authorization
   * for pending servers.
   *
   * @param baseInstructions - Optional base instructions to prepend.
   */
  getSystemPrompt(baseInstructions?: string): string {
    return buildSystemPromptSection(
      this.getAuthorizedServers(),
      this.getUnauthorizedServers(),
      baseInstructions,
    );
  }

  /** Get names of servers that are connected and authorized. */
  getAuthorizedServers(): string[] {
    const names: string[] = [];
    for (const [name, state] of this.#serverStates) {
      if (state.status === "authorized") names.push(name);
    }
    return names;
  }

  /** Get names of servers that need OAuth authorization. */
  getUnauthorizedServers(): string[] {
    const names: string[] = [];
    for (const [name, state] of this.#serverStates) {
      if (state.status === "unauthorized") names.push(name);
    }
    return names;
  }

  /** Get the full state map for all servers. */
  getServerStates(): ReadonlyMap<string, ServerState> {
    return this.#serverStates;
  }

  /** Clear the tools cache, forcing re-fetch on next getTools() call. */
  clearCache(): void {
    this.#toolsCache = undefined;
  }
}
