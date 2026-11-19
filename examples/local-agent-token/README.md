# Local Agent Token Example

A program that gets an access token for a third-party resource from the Keycard
agent running on the same machine, with no application credential, and calls
the resource with it. Uses [`@keycardai/oauth/agent`](../../packages/oauth)'s
`AgentTokenSource` and `resourceTransport`.

## How It Works

The program holds no client secret, refresh token, or session. It sends one
`IssueToken` request to the local agent over a Unix socket: the per-session
server `keycard run` starts for its child process, or the multi-zone
`keycard agent` daemon. The agent brokers the token with the developer's own
zone session and asks the developer to approve the first request for each
resource and scope set.

The socket is the first of: the `socket` option, `KEYCARD_SOCKET` (which
`keycard run` sets), or the daemon's default socket
(`~/.local/state/keycard/run/agent.sock` on macOS,
`$XDG_RUNTIME_DIR/keycard/agent.sock` on Linux).

## Prerequisites

- **Node.js 18+**, **npm**, and **pnpm** (to build `@keycardai/oauth` from source)
- **Keycard CLI**, signed in to a zone (`keycard auth signin`)
- The resource (e.g. `https://api.github.com`) registered in the zone and linked
  to the provider that issues its tokens

## Configuration

| Variable | Required | Description |
| --- | --- | --- |
| `KEYCARD_RESOURCE` | no | Resource indicator to mint for (default `https://api.github.com`) |
| `KEYCARD_URL` | no | URL to GET with the token (default `https://api.github.com/user`) |
| `KEYCARD_SCOPES` | no | Space-separated scopes |
| `KEYCARD_ORG` | no | Organization id, for the `keycard agent` daemon |
| `KEYCARD_ZONE` | no | Zone id, for the `keycard agent` daemon |
| `KEYCARD_APP_ID` | no | Application the program says it acts for |

## Run

From this directory:

```bash
(cd ../../packages/oauth && pnpm install && pnpm build)
npm install
npm run build

# Under keycard run, which sets KEYCARD_SOCKET:
keycard run -- node dist/main.js

# Or against the daemon's default socket:
keycard agent start
KEYCARD_ORG=... KEYCARD_ZONE=... node dist/main.js
```

Approve the prompt the agent shows. The program prints a prefix of the token,
its expiry, and the resource's response.

## Errors

- refused: the developer declined the prompt, the prompt expired, or the
  `keycard agent` daemon has no session for `KEYCARD_ORG` and `KEYCARD_ZONE`;
  the agent's message says which
- application not found: `KEYCARD_APP_ID` names no application in the zone
- action needed: sign in, run under `keycard run`, or repair the device key
  first; the message names the remedy
- cannot reach the agent: the message names the socket and how it was chosen

The program prints the agent's messages and the resource's response with
control and invisible characters replaced, since neither is text it wrote.
