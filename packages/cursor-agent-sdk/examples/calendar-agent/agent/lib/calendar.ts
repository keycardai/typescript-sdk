// One provider for the caller's calendar, shared by the connection and the
// server tool so both use the same configuration and token cache.
import { Keycard } from "@keycardai/cursor-agent-sdk";

export const CALENDAR_URL = "https://calendar-mcp.example.com";

export const calendarAuth = Keycard.onBehalfOf({
  zoneUrl: process.env.KEYCARD_ZONE_URL ?? "https://your-zone.keycard.cloud",
  resource: CALENDAR_URL,
  requestScopes: ["calendar.read"],
  clientId: process.env.KEYCARD_CLIENT_ID ?? "your-client-id",
  // Read when the provider runs, not at import: on Cursor hosting the
  // platform binds deployment secrets per request. Declare the name in
  // `secretNames` and set it with `agent-sdk secret set <slug> KEYCARD_CLIENT_SECRET`.
  clientSecret: { secretName: "KEYCARD_CLIENT_SECRET" },
});
