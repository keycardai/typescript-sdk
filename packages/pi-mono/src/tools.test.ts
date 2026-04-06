import { jest } from "@jest/globals";
import { jsonSchemaToTypeBox, convertMcpToolToAgentTool, convertServerTools } from "./tools.js";
import { Kind } from "@sinclair/typebox";
import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeMcpTool(overrides: Partial<Tool> = {}): Tool {
  return {
    name: "list_repos",
    description: "List repositories",
    inputSchema: {
      type: "object" as const,
      properties: {
        owner: { type: "string", description: "The owner" },
      },
      required: ["owner"],
    },
    ...overrides,
  };
}

function makeMockClient(overrides: Partial<Client> = {}): Client {
  return {
    callTool: jest.fn(),
    listTools: jest.fn(),
    ...overrides,
  } as unknown as Client;
}

// ---------------------------------------------------------------------------
// jsonSchemaToTypeBox
// ---------------------------------------------------------------------------

describe("jsonSchemaToTypeBox", () => {
  it("returns an empty Type.Object for undefined input", () => {
    const schema = jsonSchemaToTypeBox(undefined);
    expect(schema[Kind]).toBe("Object");
  });

  it("wraps a JSON schema via Type.Unsafe", () => {
    const inputSchema = {
      type: "object" as const,
      properties: { name: { type: "string" } },
    };
    const schema = jsonSchemaToTypeBox(inputSchema);
    // Type.Unsafe preserves the original schema properties
    expect(schema.type).toBe("object");
    expect(schema.properties).toEqual({ name: { type: "string" } });
  });
});

// ---------------------------------------------------------------------------
// convertMcpToolToAgentTool
// ---------------------------------------------------------------------------

describe("convertMcpToolToAgentTool", () => {
  it("sets name with server prefix", () => {
    const tool = convertMcpToolToAgentTool(makeMcpTool(), "github", makeMockClient());
    expect(tool.name).toBe("github__list_repos");
  });

  it("sets label and description", () => {
    const tool = convertMcpToolToAgentTool(makeMcpTool(), "github", makeMockClient());
    expect(tool.label).toBe("github: list_repos");
    expect(tool.description).toBe("List repositories");
  });

  it("uses fallback description when none provided", () => {
    const mcpTool = makeMcpTool({ description: undefined });
    const tool = convertMcpToolToAgentTool(mcpTool, "github", makeMockClient());
    expect(tool.description).toBe("Tool from github");
  });

  it("converts inputSchema to TypeBox", () => {
    const tool = convertMcpToolToAgentTool(makeMcpTool(), "github", makeMockClient());
    expect(tool.parameters.type).toBe("object");
  });

  it("calls client.callTool on execute with correct arguments", async () => {
    const callTool = jest.fn<Client["callTool"]>().mockResolvedValue({
      content: [{ type: "text", text: "result text" }],
    });
    const client = makeMockClient({ callTool });
    const tool = convertMcpToolToAgentTool(makeMcpTool(), "github", client);

    const result = await tool.execute("call-1", { owner: "keycardai" });

    expect(callTool).toHaveBeenCalledWith(
      { name: "list_repos", arguments: { owner: "keycardai" } },
      undefined,
      { signal: undefined },
    );
    expect(result.content).toEqual([{ type: "text", text: "result text" }]);
    expect(result.details).toBeUndefined();
  });

  it("handles null params", async () => {
    const callTool = jest.fn<Client["callTool"]>().mockResolvedValue({
      content: [{ type: "text", text: "ok" }],
    });
    const client = makeMockClient({ callTool });
    const tool = convertMcpToolToAgentTool(makeMcpTool(), "github", client);

    await tool.execute("call-1", null);

    expect(callTool).toHaveBeenCalledWith(
      { name: "list_repos", arguments: undefined },
      undefined,
      { signal: undefined },
    );
  });

  it("converts image content blocks", async () => {
    const callTool = jest.fn<Client["callTool"]>().mockResolvedValue({
      content: [{ type: "image", data: "base64data", mimeType: "image/png" }],
    });
    const client = makeMockClient({ callTool });
    const tool = convertMcpToolToAgentTool(makeMcpTool(), "github", client);

    const result = await tool.execute("call-1", {});

    expect(result.content).toEqual([
      { type: "image", data: "base64data", mimeType: "image/png" },
    ]);
  });

  it("returns fallback text when content is empty", async () => {
    const callTool = jest.fn<Client["callTool"]>().mockResolvedValue({
      content: [],
    });
    const client = makeMockClient({ callTool });
    const tool = convertMcpToolToAgentTool(makeMcpTool(), "github", client);

    const result = await tool.execute("call-1", {});

    expect(result.content).toEqual([{ type: "text", text: "(no output)" }]);
  });

  it("throws on error results", async () => {
    const callTool = jest.fn<Client["callTool"]>().mockResolvedValue({
      content: [{ type: "text", text: "something went wrong" }],
      isError: true,
    });
    const client = makeMockClient({ callTool });
    const tool = convertMcpToolToAgentTool(makeMcpTool(), "github", client);

    await expect(tool.execute("call-1", {})).rejects.toThrow("something went wrong");
  });

  it("throws 'Unknown error' when error result has no text", async () => {
    const callTool = jest.fn<Client["callTool"]>().mockResolvedValue({
      content: [],
      isError: true,
    });
    const client = makeMockClient({ callTool });
    const tool = convertMcpToolToAgentTool(makeMcpTool(), "github", client);

    await expect(tool.execute("call-1", {})).rejects.toThrow("Unknown error");
  });
});

// ---------------------------------------------------------------------------
// convertServerTools
// ---------------------------------------------------------------------------

describe("convertServerTools", () => {
  it("lists and converts all tools from a server", async () => {
    const listTools = jest.fn<Client["listTools"]>().mockResolvedValue({
      tools: [
        makeMcpTool({ name: "list_repos" }),
        makeMcpTool({ name: "get_repo", description: "Get a repo" }),
      ],
    });
    const client = makeMockClient({ listTools });

    const tools = await convertServerTools("github", client);

    expect(tools).toHaveLength(2);
    expect(tools[0].name).toBe("github__list_repos");
    expect(tools[1].name).toBe("github__get_repo");
    expect(listTools).toHaveBeenCalledTimes(1);
  });
});
