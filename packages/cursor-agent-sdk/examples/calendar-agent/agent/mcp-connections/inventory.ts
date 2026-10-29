// A back-office system the agent reads as itself: client credentials under
// the agent's own Application, one token per connection across every session,
// so schedules and webhook-created sessions work too.
import { defineConnection } from "@grok/agent-sdk/connections";
import { Keycard } from "@keycardai/cursor-agent-sdk";

export default defineConnection({
  url: "https://inventory-mcp.example.com/mcp",
  description: "Warehouse inventory, read as the agent.",
  advertiseTools: true,
  optional: true,
  auth: Keycard.asSelf({
    zoneUrl: process.env.KEYCARD_ZONE_URL ?? "https://your-zone.keycard.cloud",
    resource: "https://inventory-mcp.example.com",
    clientId: process.env.KEYCARD_CLIENT_ID ?? "your-client-id",
    clientSecret: { secretName: "KEYCARD_CLIENT_SECRET" },
  }),
});
