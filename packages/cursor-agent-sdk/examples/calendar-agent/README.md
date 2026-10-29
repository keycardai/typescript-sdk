# calendar-agent

A Cursor Agent SDK agent governed by Keycard: callers sign in with a zone
token, the calendar connection acts on behalf of the caller, the inventory
connection acts as the agent, and one server tool reuses the connection's
credential through `headersFor`.

```bash
npm install
export KEYCARD_ZONE_URL=https://your-zone.keycard.cloud
export KEYCARD_CLIENT_ID=<a password credential's identifier on the agent's Application>
export KEYCARD_CLIENT_SECRET=<its secret>
npx agent-sdk serve
```

Call the agent with a zone-issued token in `Authorization: Bearer ...`; a
request without one is admitted by `localDev()` on loopback only and has no
Keycard identity, so the calendar connection fails `principal_required`.
