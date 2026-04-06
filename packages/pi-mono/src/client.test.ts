import { jest } from "@jest/globals";
import { PiMonoClient } from "./client.js";
import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import type { AuthToolHandler } from "./types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeMockClient(authorized: boolean): Client {
  const listTools = authorized
    ? jest.fn<Client["listTools"]>().mockResolvedValue({
        tools: [
          {
            name: "list_repos",
            description: "List repos",
            inputSchema: { type: "object" as const },
          },
        ],
      })
    : jest.fn<Client["listTools"]>().mockRejectedValue(new Error("Unauthorized"));

  const callTool = jest.fn<Client["callTool"]>().mockResolvedValue({
    content: [{ type: "text", text: "ok" }],
  });

  return { listTools, callTool } as unknown as Client;
}

// ---------------------------------------------------------------------------
// PiMonoClient
// ---------------------------------------------------------------------------

describe("PiMonoClient", () => {
  describe("detectAuthStatus", () => {
    it("marks servers as authorized when listTools succeeds", async () => {
      const client = new PiMonoClient({
        servers: [{ name: "github", client: makeMockClient(true) }],
      });

      await client.detectAuthStatus();

      expect(client.getAuthorizedServers()).toEqual(["github"]);
      expect(client.getUnauthorizedServers()).toEqual([]);
    });

    it("marks servers as unauthorized when listTools fails", async () => {
      const client = new PiMonoClient({
        servers: [{ name: "github", client: makeMockClient(false) }],
      });

      await client.detectAuthStatus();

      expect(client.getAuthorizedServers()).toEqual([]);
      expect(client.getUnauthorizedServers()).toEqual(["github"]);
    });

    it("handles mixed authorized/unauthorized servers", async () => {
      const client = new PiMonoClient({
        servers: [
          { name: "github", client: makeMockClient(true) },
          { name: "slack", client: makeMockClient(false) },
          { name: "linear", client: makeMockClient(true) },
        ],
      });

      await client.detectAuthStatus();

      expect(client.getAuthorizedServers()).toEqual(["github", "linear"]);
      expect(client.getUnauthorizedServers()).toEqual(["slack"]);
    });

    it("clears previous state on re-detect", async () => {
      const toggleClient = makeMockClient(false);
      const client = new PiMonoClient({
        servers: [{ name: "github", client: toggleClient }],
      });

      await client.detectAuthStatus();
      expect(client.getUnauthorizedServers()).toEqual(["github"]);

      // Now make it succeed
      (toggleClient.listTools as jest.Mock).mockResolvedValue({ tools: [] });
      await client.detectAuthStatus();
      expect(client.getAuthorizedServers()).toEqual(["github"]);
      expect(client.getUnauthorizedServers()).toEqual([]);
    });
  });

  describe("getTools", () => {
    it("returns converted tools from authorized servers only", async () => {
      const client = new PiMonoClient({
        servers: [
          { name: "github", client: makeMockClient(true) },
          { name: "slack", client: makeMockClient(false) },
        ],
      });
      await client.detectAuthStatus();

      const tools = await client.getTools();

      expect(tools).toHaveLength(1);
      expect(tools[0].name).toBe("github__list_repos");
    });

    it("caches tools on subsequent calls", async () => {
      const mockClient = makeMockClient(true);
      const client = new PiMonoClient({
        servers: [{ name: "github", client: mockClient }],
      });
      await client.detectAuthStatus();

      const tools1 = await client.getTools();
      const tools2 = await client.getTools();

      expect(tools1).toBe(tools2); // Same reference = cached
      // listTools called once during detectAuthStatus + once during getTools
      expect(mockClient.listTools).toHaveBeenCalledTimes(2);
    });

    it("clears cache on clearCache()", async () => {
      const mockClient = makeMockClient(true);
      const client = new PiMonoClient({
        servers: [{ name: "github", client: mockClient }],
      });
      await client.detectAuthStatus();

      await client.getTools();
      client.clearCache();
      await client.getTools();

      // detectAuthStatus(1) + getTools(1) + getTools after clear(1)
      expect(mockClient.listTools).toHaveBeenCalledTimes(3);
    });

    it("returns empty array when no servers are authorized", async () => {
      const client = new PiMonoClient({
        servers: [{ name: "github", client: makeMockClient(false) }],
      });
      await client.detectAuthStatus();

      const tools = await client.getTools();
      expect(tools).toEqual([]);
    });
  });

  describe("getAuthTools", () => {
    it("returns auth tool when servers are unauthorized and generateAuthUrl provided", async () => {
      const client = new PiMonoClient({
        servers: [{ name: "github", client: makeMockClient(false) }],
        generateAuthUrl: async () => "https://auth.example.com",
      });
      await client.detectAuthStatus();

      const authTools = await client.getAuthTools();

      expect(authTools).toHaveLength(1);
      expect(authTools[0].name).toBe("request_authorization");
    });

    it("returns empty when all servers authorized", async () => {
      const client = new PiMonoClient({
        servers: [{ name: "github", client: makeMockClient(true) }],
        generateAuthUrl: async () => "https://auth.example.com",
      });
      await client.detectAuthStatus();

      const authTools = await client.getAuthTools();
      expect(authTools).toEqual([]);
    });

    it("returns empty when no generateAuthUrl provided", async () => {
      const client = new PiMonoClient({
        servers: [{ name: "github", client: makeMockClient(false) }],
      });
      await client.detectAuthStatus();

      const authTools = await client.getAuthTools();
      expect(authTools).toEqual([]);
    });
  });

  describe("getSystemPrompt", () => {
    it("includes authorized and unauthorized servers", async () => {
      const client = new PiMonoClient({
        servers: [
          { name: "github", client: makeMockClient(true) },
          { name: "slack", client: makeMockClient(false) },
        ],
      });
      await client.detectAuthStatus();

      const prompt = client.getSystemPrompt();

      expect(prompt).toContain("github");
      expect(prompt).toContain("slack");
      expect(prompt).toContain("Authorized and available");
      expect(prompt).toContain("Not yet authorized");
    });

    it("prepends base instructions", async () => {
      const client = new PiMonoClient({
        servers: [{ name: "github", client: makeMockClient(true) }],
      });
      await client.detectAuthStatus();

      const prompt = client.getSystemPrompt("You are a helpful assistant.");
      expect(prompt).toMatch(/^You are a helpful assistant\./);
    });
  });

  describe("getServerStates", () => {
    it("returns readonly map of all server states", async () => {
      const client = new PiMonoClient({
        servers: [
          { name: "github", client: makeMockClient(true) },
          { name: "slack", client: makeMockClient(false) },
        ],
      });
      await client.detectAuthStatus();

      const states = client.getServerStates();

      expect(states.size).toBe(2);
      expect(states.get("github")?.status).toBe("authorized");
      expect(states.get("slack")?.status).toBe("unauthorized");
      expect(states.get("slack")?.error).toBe("Unauthorized");
    });
  });
});
