// The caller's calendar, reached with a token exchanged from the caller's own
// Keycard token. The SDK runs `auth` before every turn and attaches the
// headers itself; the model never sees a credential.
import { defineConnection } from "@grok/agent-sdk/connections";
import { Keycard } from "@keycardai/cursor-agent-sdk";

export default defineConnection({
  url: "https://calendar-mcp.example.com/mcp",
  description: "The signed-in user's calendar.",
  advertiseTools: true,
  auth: Keycard.onBehalfOf({
    zoneUrl: process.env.KEYCARD_ZONE_URL ?? "https://your-zone.keycard.cloud",
    resource: "https://calendar-mcp.example.com",
    requestScopes: ["calendar.read"],
    clientId: process.env.KEYCARD_CLIENT_ID ?? "your-client-id",
    // Read when the provider runs, not at import: on Cursor hosting the
    // platform binds deployment secrets per request. Declare the name in
    // `secretNames` and set it with `agent-sdk secret set <slug> KEYCARD_CLIENT_SECRET`.
    clientSecret: { secretName: "KEYCARD_CLIENT_SECRET" },
  }),
});
