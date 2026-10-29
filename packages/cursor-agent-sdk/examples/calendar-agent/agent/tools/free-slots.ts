// A server tool that calls the calendar's REST API directly. `ctx.host.mcp`
// would carry only the connection's static headers, so the tool asks the
// connection's own provider for the headers the turn received (`headersFor`),
// sharing its token cache.
import { defineTool } from "@grok/agent-sdk/tools";
import { headersFor } from "@keycardai/cursor-agent-sdk";
import * as z from "zod/v4";

import { CALENDAR_URL, calendarAuth } from "../lib/calendar.js";

export default defineTool({
  description: "Free slots in the caller's calendar over the next days.",
  inputSchema: z.object({ daysAhead: z.number().int().min(1).max(30) }),
  async execute(input, ctx) {
    const { headers } = await headersFor(calendarAuth, ctx.session);
    const response = await fetch(`${CALENDAR_URL}/free?days=${input.daysAhead}`, {
      headers,
      signal: AbortSignal.timeout(10_000),
    });
    if (!response.ok) {
      return { error: `calendar returned ${response.status}` };
    }
    try {
      return await response.json();
    } catch {
      return { error: "calendar returned a body that isn't JSON" };
    }
  },
});
