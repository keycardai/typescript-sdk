import { afterEach, describe, expect, it, jest } from "@jest/globals";
import { tool } from "@langchain/core/tools";
import { createAgent } from "langchain";
import { z } from "zod";
import { Access } from "./access.js";
import { keycardGrantMiddleware } from "./middleware.js";
import { FakeToolCallingModel } from "./testUtils.js";

const ZONE = "https://zone.example.com";
const CALENDAR = "https://www.googleapis.com/calendar/v3";

const realFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = realFetch;
});

/** Record every request, answering discovery and token calls from memory. */
function stubZone(): { urls: string[] } {
  const urls: string[] = [];
  globalThis.fetch = jest.fn(async (input: unknown) => {
    const url = String(input);
    urls.push(url);
    const body = url.endsWith("/token")
      ? { access_token: "granted", token_type: "Bearer" }
      : { issuer: ZONE, token_endpoint: `${ZONE}/token` };
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }) as unknown as typeof fetch;
  return { urls };
}

describe("the hot path", () => {
  it("discovers the zone once and reuses the client across calls", async () => {
    const zone = stubZone();
    const keycard = keycardGrantMiddleware({
      zoneUrl: ZONE,
      resources: [CALENDAR],
      clientId: "agent",
      clientSecret: "shh",
    });

    const readCalendar = tool(async () => "ok", {
      name: "read_calendar",
      description: "read",
      schema: z.object({}),
    });
    const agent = createAgent({
      model: new FakeToolCallingModel("read_calendar"),
      tools: [readCalendar],
      middleware: [keycard],
    });

    const identity = Access.onBehalfOf("caller-token");
    await agent.invoke(
      { messages: [{ role: "user", content: "go" }] },
      { context: identity },
    );
    await keycard.grant({ identity }, () => undefined);
    await keycard.grant({ identity }, () => undefined);

    const discoveries = zone.urls.filter((url) => !url.endsWith("/token"));
    const tokenCalls = zone.urls.filter((url) => url.endsWith("/token"));

    expect(discoveries).toHaveLength(1);
    expect(tokenCalls).toHaveLength(3);
  });
});
