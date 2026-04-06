/**
 * Auth-aware system prompt generation.
 *
 * Generates a section to append to the agent's system prompt
 * that describes which MCP servers are available vs pending authorization.
 */

/**
 * Build a system prompt section describing MCP server auth status.
 *
 * @param authorizedServers - Names of servers that are connected and authorized.
 * @param unauthorizedServers - Names of servers that need OAuth authorization.
 * @param baseInstructions - Optional base instructions to prepend.
 * @returns A system prompt string to append to the agent's instructions.
 */
export function buildSystemPromptSection(
  authorizedServers: string[],
  unauthorizedServers: string[],
  baseInstructions?: string,
): string {
  const lines: string[] = [];

  if (baseInstructions) {
    lines.push(baseInstructions, "");
  }

  lines.push("## MCP Server Status");

  if (authorizedServers.length > 0) {
    lines.push(`Authorized and available: ${authorizedServers.join(", ")}`);
  }

  if (unauthorizedServers.length > 0) {
    lines.push(
      `Not yet authorized (tools unavailable): ${unauthorizedServers.join(", ")}`,
      "",
      "When the user asks about or needs an unauthorized service, use the",
      "request_authorization tool to initiate the OAuth flow for that service.",
    );
  }

  if (authorizedServers.length === 0 && unauthorizedServers.length === 0) {
    lines.push("No MCP servers are configured.");
  } else if (authorizedServers.length === 0) {
    lines.push(
      "",
      "No MCP servers are currently authorized.",
      "Use the request_authorization tool when the user wants to connect a service.",
    );
  }

  return lines.join("\n");
}
