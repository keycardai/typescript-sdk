/**
 * Shared types for the @keycardai/pi-mono integration.
 *
 * Re-exports the pi-mono AgentTool types and defines Keycard-specific interfaces
 * for MCP server configuration and auth handling.
 */

import type { Client } from "@modelcontextprotocol/sdk/client/index.js";

// ---------------------------------------------------------------------------
// Re-export pi-mono types that consumers need
// ---------------------------------------------------------------------------

export type {
  AgentTool,
  AgentToolResult,
  AgentToolUpdateCallback,
} from "@mariozechner/pi-agent-core";

// ---------------------------------------------------------------------------
// MCP server configuration
// ---------------------------------------------------------------------------

/** Auth status of an MCP server after connection attempt. */
export type ServerAuthStatus = "authorized" | "unauthorized" | "error";

/** Tracked state for a connected (or failed) MCP server. */
export interface ServerState {
  name: string;
  status: ServerAuthStatus;
  /** The MCP client for this server (set when authorized). */
  client?: Client;
  /** Error message if status is "error". */
  error?: string;
}

// ---------------------------------------------------------------------------
// Auth tool handler
// ---------------------------------------------------------------------------

/**
 * Pluggable handler for delivering OAuth authorization links to users.
 *
 * Implement this interface to customize how auth links are presented —
 * e.g., posting to Slack, rendering in a web UI, or printing to console.
 *
 * Follows the same pattern as the Python SDK's AuthToolHandler.
 */
export interface AuthToolHandler {
  /**
   * Called when a server needs OAuth authorization.
   *
   * @param serverName - The name of the MCP server requiring auth.
   * @param authUrl - The full OAuth authorization URL the user should visit.
   * @param reason - Optional reason the agent wants access (from the agent's tool call).
   * @returns A message string for the agent to display to the user.
   */
  handleAuthRequest(
    serverName: string,
    authUrl: string,
    reason?: string,
  ): Promise<string>;

  /**
   * Called when an error occurs during auth flow setup.
   * Optional — defaults to returning an error message string.
   */
  handleAuthError?(serverName: string, error: Error): Promise<string>;
}
