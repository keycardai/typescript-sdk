// The built-in HTTP session channel. A Keycard zone token admits the caller
// as a Keycard user principal; `localDev()` keeps local tooling working.
// Every Keycard principal's bearer is retained in process memory for the
// on-behalf-of connection below, and never written to the session record.
import { bearerAuth, httpChannel, localDev } from "@grok/agent-sdk/channels";
import { keycardAuth } from "@keycardai/cursor-agent-sdk";

export default httpChannel({
  auth: [
    bearerAuth(
      keycardAuth({
        zoneUrl: process.env.KEYCARD_ZONE_URL ?? "https://your-zone.keycard.cloud",
        audience: "https://calendar-agent.example.com",
      }),
    ),
    localDev(),
  ],
});
