// A server tool that calls the calendar's REST API directly. `ctx.host.mcp`
// would carry only the connection's static headers, so the tool asks the same
// provider for the headers the turn received (`headersFor`), sharing its cache.
import { defineTool } from "@grok/agent-sdk/tools";
import { headersFor, Keycard } from "@keycardai/cursor-agent-sdk";
import * as z from "zod/v4";

const calendar = Keycard.onBehalfOf({
  zoneUrl: process.env.KEYCARD_ZONE_URL ?? "https://your-zone.keycard.cloud",
  resource: "https://calendar-mcp.example.com",
  clientId: process.env.KEYCARD_CLIENT_ID ?? "your-client-id",
  clientSecret: { secretName: "KEYCARD_CLIENT_SECRET" },
});

export default defineTool({
  description: "Free slots in the caller's calendar over the next days.",
  inputSchema: z.object({ daysAhead: z.number().int().min(1).max(30) }),
  async execute(input, ctx) {
    const { headers } = await headersFor(calendar, ctx.session);
    const response = await fetch(
      `https://calendar-mcp.example.com/free?days=${input.daysAhead}`,
      { headers },
    );
    return response.json();
  },
});
