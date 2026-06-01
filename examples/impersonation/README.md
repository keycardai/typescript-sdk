# Impersonation Example

A background agent that obtains a resource-scoped access token on behalf of a
named user via Keycard token exchange (RFC 8693), without the user being
present. Uses [`@keycardai/oauth`](../../packages/oauth)'s
`TokenExchangeClient.impersonate()`.

## How It Works

The agent is a confidential client (`client_secret_basic`). On each call,
`impersonate()`:

1. Mints an **actor token** from the agent's own credentials via a
   `client_credentials` grant.
2. Builds an unsigned **substitute-user** assertion carrying the target user
   identifier (`subject_token_type`:
   `urn:keycard:params:oauth:token-type:substitute-user`).
3. Exchanges them for a resource token whose `sub` is the target user and whose
   `act` chain identifies this agent for audit.

The user must have previously granted access (a delegated grant) for the
requested resource. **Impersonation is forbidden by default** — an
administrator must explicitly allow specific applications to impersonate.

## Prerequisites

- Node.js 18+ and pnpm
- Access to Keycard Console and a Keycard zone

## Setup in Keycard Console

1. **Set `KEYCARD_ZONE_URL`** to your zone URL from the Zone Settings.
2. **Create a provider** (e.g. `https://github.com`) and a **resource**
   (e.g. `https://api.github.com`) linked to it.
3. **Register this agent** as a confidential client (password credential) and
   add the resource as a dependency.
4. **Ensure the target user has a delegated grant** for the resource.
5. **Add a policy permitting impersonation** for this application.

## Configuration

Configure via environment variables (loaded from a local `.env` file via
[dotenv](https://github.com/motdotla/dotenv), or set in the shell). Copy the
template and fill it in:

```bash
cp .env.example .env
```

| Variable | Required | Description |
| --- | --- | --- |
| `KEYCARD_ZONE_URL` | yes | Keycard zone URL for metadata discovery |
| `KEYCARD_CLIENT_ID` | yes | Confidential client ID |
| `KEYCARD_CLIENT_SECRET` | yes | Confidential client secret |
| `KEYCARD_USER` | yes | Target user identifier (becomes `sub`) |
| `KEYCARD_RESOURCE` | no | Target resource URI |
| `KEYCARD_SCOPES` | no | Space-separated scopes |

## Run

This example depends on the OAuth package **source** in this repo
(`@keycardai/oauth` → `file:../../packages/oauth`), so you can run it before the
SDK is published. Build the SDK first, then install and run the example.

From the repo root, build the OAuth package:

```bash
pnpm --filter @keycardai/oauth build
```

Then, from this directory:

```bash
# Standalone install so the local file: dependency is linked instead of the
# published package (this example is not a pnpm workspace member).
pnpm install --ignore-workspace
pnpm build
pnpm start
```

On success it prints the issued token's type, expiry, and granted scopes. If
the user is unknown you'll see `invalid_grant`; if the agent isn't permitted to
impersonate you'll see `unauthorized_client`.
