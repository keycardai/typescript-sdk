# Impersonation Example

A background agent that obtains a resource-scoped access token on behalf of a
named user via Keycard token exchange (RFC 8693), without the user being
present. Uses [`@keycardai/oauth`](../../packages/oauth)'s
`TokenExchangeClient.impersonate()`.

## How It Works

The agent is a confidential client (`client_secret_basic`). `impersonate()`
performs a single token exchange, authenticated with the agent's own
credentials, where the subject token is an unsigned substitute-user assertion
(`subject_token_type`: `urn:keycard:params:oauth:token-type:substitute-user`)
carrying the target user identifier. The issued token's `sub` is the target
user; the authorization server derives the acting party from the
authenticated client and records it in the `act` claim chain for audit.

The user must have previously granted access (a delegated grant) for the
requested resource. **Impersonation is forbidden by default**: an
administrator must explicitly allow specific applications to impersonate.

## Prerequisites

- **Node.js 18+** and **pnpm**
- **Keycard account**: sign up at [console.keycard.ai](https://console.keycard.ai)
- **Configured zone** with an identity provider

## Keycard Console Setup

1. Create a provider and a resource (e.g. `https://api.github.com`) linked
   to it.
2. Register this agent as a confidential client (password credential) and add
   the resource as a dependency.
3. Ensure the target user has a delegated grant for the resource.
4. Add a policy permitting this application to impersonate.

## Configuration

| Variable | Required | Description |
| --- | --- | --- |
| `KEYCARD_ZONE_URL` | yes | Keycard zone URL for metadata discovery |
| `KEYCARD_CLIENT_ID` | yes | Confidential client ID |
| `KEYCARD_CLIENT_SECRET` | yes | Confidential client secret |
| `KEYCARD_USER` | yes | Target user identifier (becomes `sub`) |
| `KEYCARD_RESOURCE` | yes | Target resource URI |
| `KEYCARD_SCOPES` | no | Space-separated scopes |

## Run

From this directory:

```bash
pnpm install
pnpm build

KEYCARD_ZONE_URL="https://your-zone.keycard.cloud" \
KEYCARD_CLIENT_ID="background-agent" \
KEYCARD_CLIENT_SECRET="..." \
KEYCARD_USER="alice@example.com" \
KEYCARD_RESOURCE="https://api.github.com" \
pnpm start
```

On success it prints the issued token's type, expiry, and granted scopes.

## Errors

- `invalid_grant`: the user is unknown or not impersonatable by this client
- `unauthorized_client`: this client is not permitted to impersonate
