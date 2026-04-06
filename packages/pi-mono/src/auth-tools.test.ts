import { jest } from "@jest/globals";
import {
  DefaultAuthToolHandler,
  ConsoleAuthToolHandler,
  createAuthRequestTool,
} from "./auth-tools.js";
import type { AuthToolHandler } from "./types.js";

// ---------------------------------------------------------------------------
// DefaultAuthToolHandler
// ---------------------------------------------------------------------------

describe("DefaultAuthToolHandler", () => {
  const handler = new DefaultAuthToolHandler();

  it("returns auth URL message with reason", async () => {
    const msg = await handler.handleAuthRequest("github", "https://auth.example.com", "needs PR access");
    expect(msg).toContain("github");
    expect(msg).toContain("https://auth.example.com");
    expect(msg).toContain("needs PR access");
  });

  it("returns auth URL message without reason", async () => {
    const msg = await handler.handleAuthRequest("github", "https://auth.example.com");
    expect(msg).toContain("github");
    expect(msg).toContain("https://auth.example.com");
    expect(msg).not.toContain("undefined");
  });

  it("returns error message", async () => {
    const msg = await handler.handleAuthError!("github", new Error("timeout"));
    expect(msg).toContain("github");
    expect(msg).toContain("timeout");
  });
});

// ---------------------------------------------------------------------------
// ConsoleAuthToolHandler
// ---------------------------------------------------------------------------

describe("ConsoleAuthToolHandler", () => {
  const handler = new ConsoleAuthToolHandler();

  it("prints to console and returns confirmation", async () => {
    const logSpy = jest.spyOn(console, "log").mockImplementation(() => {});
    const msg = await handler.handleAuthRequest("slack", "https://auth.example.com/slack");
    expect(logSpy).toHaveBeenCalled();
    expect(msg).toContain("printed to the console");
    logSpy.mockRestore();
  });

  it("prints error to stderr", async () => {
    const errorSpy = jest.spyOn(console, "error").mockImplementation(() => {});
    await handler.handleAuthError!("slack", new Error("failed"));
    expect(errorSpy).toHaveBeenCalled();
    errorSpy.mockRestore();
  });
});

// ---------------------------------------------------------------------------
// createAuthRequestTool
// ---------------------------------------------------------------------------

describe("createAuthRequestTool", () => {
  const mockHandler: AuthToolHandler = {
    handleAuthRequest: jest.fn<AuthToolHandler["handleAuthRequest"]>()
      .mockResolvedValue("Please visit the auth link"),
    handleAuthError: jest.fn<NonNullable<AuthToolHandler["handleAuthError"]>>()
      .mockResolvedValue("Auth failed"),
  };

  const generateAuthUrl = jest.fn<(name: string) => Promise<string>>()
    .mockResolvedValue("https://auth.example.com/authorize?server=github");

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("creates a tool with correct metadata", () => {
    const tool = createAuthRequestTool(["github", "slack"], mockHandler, generateAuthUrl);
    expect(tool.name).toBe("request_authorization");
    expect(tool.label).toBe("Request Authorization");
    expect(tool.description).toContain("github, slack");
  });

  it("calls generateAuthUrl and handler on execute", async () => {
    const tool = createAuthRequestTool(["github"], mockHandler, generateAuthUrl);
    const result = await tool.execute("call-1", { service: "github", reason: "need PRs" });

    expect(generateAuthUrl).toHaveBeenCalledWith("github");
    expect(mockHandler.handleAuthRequest).toHaveBeenCalledWith(
      "github",
      "https://auth.example.com/authorize?server=github",
      "need PRs",
    );
    expect(result.content[0]).toEqual({ type: "text", text: "Please visit the auth link" });
  });

  it("rejects unknown services", async () => {
    const tool = createAuthRequestTool(["github"], mockHandler, generateAuthUrl);
    const result = await tool.execute("call-1", { service: "unknown" });

    expect(generateAuthUrl).not.toHaveBeenCalled();
    expect(result.content[0]).toEqual(
      expect.objectContaining({
        type: "text",
        text: expect.stringContaining("not in the list"),
      }),
    );
  });

  it("handles generateAuthUrl errors gracefully", async () => {
    const failingGenerate = jest.fn<(name: string) => Promise<string>>()
      .mockRejectedValue(new Error("network error"));
    const tool = createAuthRequestTool(["github"], mockHandler, failingGenerate);
    const result = await tool.execute("call-1", { service: "github" });

    expect(mockHandler.handleAuthError).toHaveBeenCalledWith("github", expect.any(Error));
    expect(result.content[0]).toEqual({ type: "text", text: "Auth failed" });
  });

  it("handles missing params gracefully", async () => {
    const tool = createAuthRequestTool(["github"], mockHandler, generateAuthUrl);
    const result = await tool.execute("call-1", null);

    // Empty string from typeof check — won't match any server
    expect(result.content[0]).toEqual(
      expect.objectContaining({
        type: "text",
        text: expect.stringContaining("not in the list"),
      }),
    );
  });
});
