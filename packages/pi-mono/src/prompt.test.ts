import { buildSystemPromptSection } from "./prompt.js";

describe("buildSystemPromptSection", () => {
  it("lists authorized servers", () => {
    const result = buildSystemPromptSection(["github", "slack"], []);
    expect(result).toContain("Authorized and available: github, slack");
  });

  it("lists unauthorized servers with instructions", () => {
    const result = buildSystemPromptSection([], ["linear"]);
    expect(result).toContain("Not yet authorized (tools unavailable): linear");
    expect(result).toContain("request_authorization");
  });

  it("shows both authorized and unauthorized", () => {
    const result = buildSystemPromptSection(["github"], ["linear", "slack"]);
    expect(result).toContain("Authorized and available: github");
    expect(result).toContain("Not yet authorized (tools unavailable): linear, slack");
  });

  it("shows no-servers-configured when both lists empty", () => {
    const result = buildSystemPromptSection([], []);
    expect(result).toContain("No MCP servers are configured");
  });

  it("shows none-authorized message when only unauthorized exist", () => {
    const result = buildSystemPromptSection([], ["github"]);
    expect(result).toContain("No MCP servers are currently authorized");
  });

  it("prepends base instructions", () => {
    const result = buildSystemPromptSection(["github"], [], "You are a helpful bot.");
    expect(result).toMatch(/^You are a helpful bot\./);
    expect(result).toContain("Authorized and available: github");
  });

  it("always includes the header", () => {
    const result = buildSystemPromptSection(["github"], []);
    expect(result).toContain("## MCP Server Status");
  });
});
