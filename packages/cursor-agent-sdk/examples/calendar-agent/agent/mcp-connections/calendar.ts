// The caller's calendar, reached with a token exchanged from the caller's own
// Keycard token. The SDK runs `auth` before every turn and attaches the
// headers itself; the model never sees a credential.
import { defineConnection } from "@grok/agent-sdk/connections";

import { CALENDAR_URL, calendarAuth } from "../lib/calendar.js";

export default defineConnection({
  url: `${CALENDAR_URL}/mcp`,
  description: "The signed-in user's calendar.",
  advertiseTools: true,
  auth: calendarAuth,
});
