/**
 * MCP tool → pi-mono AgentTool conversion.
 *
 * Converts MCP tools (JSON Schema parameters) into pi-mono AgentTool instances
 * (TypeBox parameters) that call back to the MCP server via the MCP client.
 */

import { Type } from "@sinclair/typebox";
import type { TSchema } from "@sinclair/typebox";
import type { AgentTool, AgentToolResult } from "@mariozechner/pi-agent-core";
import type { TextContent, ImageContent } from "@mariozechner/pi-ai";
import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import type { Tool, CallToolResult, CompatibilityCallToolResult } from "@modelcontextprotocol/sdk/types.js";

/** The union type returned by Client.callTool(). */
type CallToolResponse = CallToolResult | CompatibilityCallToolResult;

/** Type guard: does the callTool response have a `content` array? */
function hasContent(result: CallToolResponse): result is CallToolResult {
  return "content" in result && Array.isArray(result.content);
}

/**
 * Convert an MCP JSON Schema into a TypeBox TSchema.
 *
 * Uses Type.Unsafe() to pass the JSON schema through as-is.
 * TypeBox's Unsafe() accepts any valid JSON schema while preserving
 * type inference — avoids deep recursive conversion of arbitrary schemas.
 */
export function jsonSchemaToTypeBox(jsonSchema: Tool["inputSchema"] | undefined): TSchema {
  if (!jsonSchema) {
    return Type.Object({});
  }
  return Type.Unsafe(jsonSchema);
}

/**
 * Extract content from an MCP CallToolResult into pi-mono's format.
 *
 * MCP's TextContent/ImageContent types are structurally compatible with
 * pi-mono's — both use { type: "text", text } and { type: "image", data, mimeType }.
 */
function mcpResultToAgentToolResult(
  result: CallToolResponse,
): AgentToolResult<undefined> {
  const content: (TextContent | ImageContent)[] = [];

  if (hasContent(result)) {
    for (const block of result.content) {
      if (block.type === "text") {
        content.push({ type: "text", text: block.text });
      } else if (block.type === "image") {
        content.push({
          type: "image",
          data: block.data,
          mimeType: block.mimeType,
        });
      }
    }
  }

  if (content.length === 0) {
    content.push({ type: "text", text: "(no output)" });
  }

  return { content, details: undefined };
}

/**
 * Extract error text from a CallToolResult's content blocks.
 */
function extractErrorText(result: CallToolResponse): string {
  if (!hasContent(result)) return "Unknown error";
  return (
    result.content
      .filter((c): c is typeof c & { type: "text" } => c.type === "text")
      .map((c) => c.text)
      .join("\n") || "Unknown error"
  );
}

/**
 * Validate and extract params as a plain object for MCP callTool.
 * The pi-mono AgentTool execute() receives `unknown` (Static<TSchema>),
 * but MCP callTool expects Record<string, unknown> | undefined.
 */
function toCallToolArguments(params: unknown): Record<string, unknown> | undefined {
  if (params == null) return undefined;
  if (typeof params === "object" && !Array.isArray(params)) {
    return params as Record<string, unknown>; // narrowed via typeof check
  }
  return undefined;
}

/**
 * Convert a single MCP tool into a pi-mono AgentTool.
 *
 * @param mcpTool - The MCP tool definition (name, description, inputSchema).
 * @param serverName - Name of the MCP server this tool belongs to.
 * @param client - The MCP client instance to use for calling the tool.
 * @returns A pi-mono AgentTool that proxies execution to the MCP server.
 */
export function convertMcpToolToAgentTool(
  mcpTool: Tool,
  serverName: string,
  client: Client,
): AgentTool {
  const toolName = `${serverName}__${mcpTool.name}`;
  const description = mcpTool.description ?? `Tool from ${serverName}`;
  const parameters = jsonSchemaToTypeBox(mcpTool.inputSchema);
  const label = `${serverName}: ${mcpTool.name}`;

  return {
    name: toolName,
    description,
    label,
    parameters,

    async execute(
      _toolCallId: string,
      params: unknown,
      signal?: AbortSignal,
    ): Promise<AgentToolResult<undefined>> {
      const result = await client.callTool(
        { name: mcpTool.name, arguments: toCallToolArguments(params) },
        undefined,
        { signal },
      );

      if (result.isError) {
        throw new Error(extractErrorText(result));
      }

      return mcpResultToAgentToolResult(result);
    },
  };
}

/**
 * Convert all tools from an MCP server into pi-mono AgentTool instances.
 *
 * @param serverName - Name of the MCP server.
 * @param client - Connected MCP client for this server.
 * @returns Array of pi-mono AgentTool instances.
 */
export async function convertServerTools(
  serverName: string,
  client: Client,
): Promise<AgentTool[]> {
  const { tools } = await client.listTools();
  return tools.map((tool) => convertMcpToolToAgentTool(tool, serverName, client));
}
