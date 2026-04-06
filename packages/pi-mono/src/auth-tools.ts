/**
 * Auth tool handlers and the "request_authorization" AgentTool.
 *
 * Follows the same pluggable AuthToolHandler pattern as the Python SDK.
 * The agent can call request_authorization to trigger an OAuth flow
 * for a server that hasn't been authorized yet.
 */

import { Type } from "@sinclair/typebox";
import type { AgentTool, AgentToolResult } from "@mariozechner/pi-agent-core";
import type { AuthToolHandler } from "./types.js";

// ---------------------------------------------------------------------------
// Built-in AuthToolHandler implementations
// ---------------------------------------------------------------------------

/**
 * Default auth handler — returns the auth URL as a message string.
 * The agent can then display this to the user in whatever UI it's running in.
 */
export class DefaultAuthToolHandler implements AuthToolHandler {
  async handleAuthRequest(
    serverName: string,
    authUrl: string,
    reason?: string,
  ): Promise<string> {
    const msg = reason
      ? `To use ${serverName} (${reason}), please authorize by visiting:\n${authUrl}`
      : `To use ${serverName}, please authorize by visiting:\n${authUrl}`;
    return msg;
  }

  async handleAuthError(serverName: string, error: Error): Promise<string> {
    return `Failed to generate authorization link for ${serverName}: ${error.message}`;
  }
}

/**
 * Console auth handler — prints the auth URL to stdout.
 * Suitable for CLI applications.
 */
export class ConsoleAuthToolHandler implements AuthToolHandler {
  async handleAuthRequest(
    serverName: string,
    authUrl: string,
    reason?: string,
  ): Promise<string> {
    const header = reason
      ? `\n🔑 Authorize ${serverName} (${reason}):`
      : `\n🔑 Authorize ${serverName}:`;
    console.log(header);
    console.log(`   ${authUrl}\n`);
    return `Authorization link for ${serverName} has been printed to the console.`;
  }

  async handleAuthError(serverName: string, error: Error): Promise<string> {
    console.error(`\n❌ Auth error for ${serverName}: ${error.message}\n`);
    return `Failed to generate authorization link for ${serverName}: ${error.message}`;
  }
}

// ---------------------------------------------------------------------------
// Auth AgentTool factory
// ---------------------------------------------------------------------------

/**
 * Create a pi-mono AgentTool that the agent can call to request OAuth
 * authorization for a pending server.
 *
 * @param unauthorizedServers - Names of servers that need authorization.
 * @param authHandler - Handler that delivers the auth link to the user.
 * @param generateAuthUrl - Function that generates the OAuth authorization URL for a server.
 * @returns An AgentTool the agent can invoke to request authorization.
 */
export function createAuthRequestTool(
  unauthorizedServers: string[],
  authHandler: AuthToolHandler,
  generateAuthUrl: (serverName: string) => Promise<string>,
): AgentTool {
  const serviceList = unauthorizedServers.join(", ");

  return {
    name: "request_authorization",
    description:
      `Request user authorization for services that need it. ` +
      `Available services: ${serviceList}. ` +
      `Call this when the user wants to use one of these services.`,
    label: "Request Authorization",
    parameters: Type.Object({
      service: Type.String({
        description: `The service to authorize. One of: ${serviceList}`,
      }),
      reason: Type.Optional(
        Type.String({
          description: "Why the agent needs access to this service.",
        }),
      ),
    }),

    async execute(
      _toolCallId: string,
      params: unknown,
    ): Promise<AgentToolResult<undefined>> {
      const p = (params != null && typeof params === "object" ? params : {}) as Record<string, unknown>;
      const service = typeof p.service === "string" ? p.service : "";
      const reason = typeof p.reason === "string" ? p.reason : undefined;

      if (!unauthorizedServers.includes(service)) {
        return {
          content: [
            {
              type: "text",
              text: `Service "${service}" is not in the list of unauthorized services. Available: ${serviceList}`,
            },
          ],
          details: undefined,
        };
      }

      try {
        const authUrl = await generateAuthUrl(service);
        const message = await authHandler.handleAuthRequest(service, authUrl, reason);
        return {
          content: [{ type: "text", text: message }],
          details: undefined,
        };
      } catch (error) {
        const errMessage = authHandler.handleAuthError
          ? await authHandler.handleAuthError(
              service,
              error instanceof Error ? error : new Error(String(error)),
            )
          : `Failed to generate auth link for ${service}: ${error}`;
        return {
          content: [{ type: "text", text: errMessage }],
          details: undefined,
        };
      }
    },
  };
}
