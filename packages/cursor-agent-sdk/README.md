# @keycardai/cursor-agent-sdk

> Preview. Keycard auth for [Cursor Agent SDK](https://www.npmjs.com/package/@grok/agent-sdk) agents: a zone token verifier for a channel's `bearerAuth` policy, and Keycard-backed connection auth that acts as the agent, on behalf of the caller, or for a mapped user.

Two adapters, each one plugging into an SDK primitive instead of wrapping it:

| Adapter | SDK primitive | What it does |
| --- | --- | --- |
| `keycardAuth()` | `bearerAuth(verify)` in a channel's auth policy chain | Verifies a zone-issued bearer and returns the SDK's `AuthContext` for the caller. |
| `Keycard.asSelf()`, `Keycard.onBehalfOf()`, `Keycard.impersonate()` | `defineConnection({ auth })` | Returns the headers a connection sends on this turn, minted by the zone for the agent, the caller, or a mapped user. |

Spec: `specs/framework-integrations/cursor-agent-sdk.md` in
[keycard-sdk-spec](https://github.com/keycardai/keycard-sdk-spec).

## Installation

```bash
pnpm add @keycardai/cursor-agent-sdk
```

`@grok/agent-sdk` is a peer dependency, pinned to `>=0.3.0 <0.4.0`: this
package was built and verified against the 0.3.0 type definitions. The SDK is
pre-1.0 with frequent releases (it was `@cursor/bdk` before 0.3.0), so the
range stops at the next untested minor rather than tracking `^`; widen it only
after re-running this package's tests against the newer SDK.

The SDK is imported for types only (`SessionInfo`, `AuthContext`,
`ConnectionAuthProvider`, `ConnectionAuthResult`, `SecretRef`), so nothing
here loads SDK code or inherits its `node >=22.13` floor. ESM only.

## 1. Verify the caller: `keycardAuth()`

```ts title="agent/channels/http.ts"
import { bearerAuth, httpChannel, localDev } from "@grok/agent-sdk/channels";
import { keycardAuth } from "@keycardai/cursor-agent-sdk";

export default httpChannel({
  auth: [
    bearerAuth(keycardAuth({ zoneUrl: process.env.KEYCARD_ZONE_URL!, audience: "https://agent.example.com" })),
    localDev(),
  ],
});
```

`bearerAuth`'s verifier can only admit (return an `AuthContext`) or pass
(return null), so `keycardAuth` returns null for a bearer this zone did not
issue, for a zone token that does not verify, and for one missing a
`requiredScopes` entry, and the chain continues. A deployment that must refuse
such a request places no admitting policy after the Keycard entry. That is the
one place this package differs from `@keycardai/eve`, whose `AuthFn` can
reject and stop.

A verified bearer becomes `{ authenticator: "keycard", principalId: sub,
principalType: "user", attributes }`, with the token's string claims and `iss`
projected onto `attributes`. The SDK persists `AuthContext` in
`sessions/<id>/session.json`, so the token itself is never placed on it. It is
retained for a later on-behalf-of exchange in a process-local store instead
(`retainSubjectToken: "memory"`, the default). Pass
`retainSubjectToken: "attributes"` when turns run in a different process from
the request that authenticated the caller; that accepts a user bearer at rest
in the session record for the session's lifetime. `"none"` retains nothing.

On Cursor hosting the built-in session, MCP and playground routes also sit
behind the deployment alias token (`X-Agent-Alias-Token`); a Keycard bearer
adds a per-user identity on top of it. For end users calling the agent
directly, a custom `httpChannel` route opts out with
`[bearerAuth(keycardAuth(...)), publicEndpoint()]`, and because
`publicEndpoint()` admits everyone as an anonymous principal, the handler must
reject any request whose `auth.authenticator` is not `"keycard"` before it
sends a message.

## 2. Acquire resource tokens: connection auth

```ts title="agent/mcp-connections/calendar.ts"
import { defineConnection } from "@grok/agent-sdk/connections";
import { Keycard } from "@keycardai/cursor-agent-sdk";

export default defineConnection({
  url: "https://calendar-mcp.example.com/mcp",
  advertiseTools: true,
  auth: Keycard.onBehalfOf({
    zoneUrl: process.env.KEYCARD_ZONE_URL!,
    resource: "https://calendar-mcp.example.com",
    requestScopes: ["calendar.read"],
    clientId: process.env.KEYCARD_CLIENT_ID!,
    clientSecret: { secretName: "KEYCARD_CLIENT_SECRET" },
  }),
});
```

The SDK runs `auth` on the host before every model turn (HTTP and SSE
connections only) and merges the returned headers over the connection's static
`headers`. The token never enters the transcript and never reaches the model.

- `Keycard.onBehalfOf()` exchanges the caller's own token, the one
  `keycardAuth()` retained for the session's Keycard principal, for the
  connection's `resource`. The default pattern for an agent that acts for
  whoever called it.
- `Keycard.asSelf()` runs client credentials under the agent's own Application,
  ignoring `session.auth`: one token per connection across every session, so
  it works on schedules and webhook-created sessions.
- `Keycard.impersonate()` uses the zone's substitute-user exchange for a user
  the agent holds no token for: by default the session's Keycard principal, or
  a `userIdentifier(auth)` function that maps any principal to a zone user. It
  is for jobs with no caller present, needs an explicit zone policy granting
  the Application impersonation, and its authority lasts as long as the
  session.

Nothing falls back to the agent's authority. A user-pattern connection in a
session with no Keycard user principal (`auth` null, set by another policy,
a `"service"` principal, or another zone's `iss`) throws `principal_required`;
an `onBehalfOf` turn whose token was never retained in this process throws
`subject_token_unavailable`; an expired one throws `subject_token_expired`
after a decode-only `exp` check that costs no round trip. A thrown provider
fails the turn, or skips the connection when it is advertised with
`optional: true`.

Credentials go in as `clientId` plus `clientSecret` (shorthand for a
`ClientSecret`) or as `applicationCredential` (any `ApplicationCredential`,
including assertion-based workload credentials). `clientSecret` also accepts
the SDK's `SecretRef` (`{ secretName }`), read from `process.env` when the
provider runs rather than when the module is imported: on Cursor hosting the
platform binds a deployment's secrets per request, after discovery imported
the module with none of them present. Declare the name in `secretNames` and
set it with `agent-sdk secret set <slug> KEYCARD_CLIENT_SECRET`. An unset
secret is a call-time `credential_unavailable` naming the variable.

Every factory caches the minted token per principal (one slot for `asSelf`)
until `expirySkewSeconds` (default 60) before expiry, keyed by the principal
and never by `session.continuationKey`, and builds one warm zone client.

### Server tools and route handlers: `headersFor()`

`ctx.host.mcp` and a route handler's `host.mcp` receive a connection's static
headers only; the SDK never runs `auth` for them. Code on those paths asks the
same provider for what the turn received:

```ts
import { headersFor, Keycard } from "@keycardai/cursor-agent-sdk";

const calendar = Keycard.onBehalfOf({ ... });

async execute(input, ctx) {
  const { headers } = await headersFor(calendar, ctx.session);
  return fetch("https://calendar-mcp.example.com/free", { headers });
}
```

It shares the provider's cache and throws the same errors. It is not called
`grant()` because `@keycardai/langchain`'s `grant()` yields an `AccessContext`
with per-resource errors, a contract this seam does not keep.

## What v1 does not do

- **On-behalf-of across processes.** The caller's token lives in process
  memory by default. A turn that runs in a process that never saw it (another
  replica, a restart) fails closed with `subject_token_unavailable`; the
  caller fixes it by calling again. `retainSubjectToken: "attributes"` trades
  that for a bearer at rest in the session record.
- **No sign-in pause from the callback.** The SDK's `action.auth_requested`
  pause fires only for host OAuth (`oauth: true`) connections, and an `auth`
  callback cannot trigger it, so a denied grant or an expired token is a
  failed turn, never a prompt to sign in. Host OAuth itself works against a
  Keycard zone unchanged, as one host-level identity for every caller; it is
  the single-identity baseline, not the multi-user path, and cannot be
  combined with `auth` on one connection.
- **Hosted agents need a stored client secret.** Cursor hosting documents no
  workload identity, so the agent authenticates with a `ClientSecret` from a
  deployment secret. Self-hosted agents with a platform OIDC token use
  `WorkloadIdentity` instead.

## Parity with `@keycardai/eve`

| `@keycardai/eve` | `@keycardai/cursor-agent-sdk` |
| --- | --- |
| `keycardAuth()` as an `AuthFn` that returns null, rejects, or admits | `keycardAuth()` as a `bearerAuth` verifier that returns null or admits |
| `Keycard.asSelf()`, `Keycard.onBehalfOf()`, `Keycard.impersonate()` returning `getToken` definitions | the same three, returning `ConnectionAuthProvider` functions |
| `retainSubjectToken`, `subjectTokens`, `subjectTokenExpired()` | the same |
| `Keycard.interactive()` and eve's durable parks | none: the SDK has no callback-triggered pause |
| fake zone client from `@keycardai/eve/testing` | fake zone client from `@keycardai/cursor-agent-sdk/testing` |

## Testing offline

```ts
import { fakeZoneClient, keycardPrincipal, session, validJwt } from "@keycardai/cursor-agent-sdk/testing";
import { Keycard, memorySubjectTokenStore } from "@keycardai/cursor-agent-sdk";

const client = fakeZoneClient();
const subjectTokens = memorySubjectTokenStore();
subjectTokens.set("https://zone.example.com|user-1", validJwt(3600));

const auth = Keycard.onBehalfOf({ resource: "https://calendar.example.com", client, subjectTokens });
const { headers } = await auth(session(keycardPrincipal()));
client.calls.exchanges; // one exchange for user-1's token
```

`fakeZoneClient()` records every exchange, impersonation and client-credentials
call and can fail one resource or every call; an injected `client` supersedes
`zoneUrl`. `keycardAuth()` takes a `verify` seam in place of the JWKS-backed
verifier. The SDK's own seam also works: a connection under test can declare
`auth: async () => ({ headers: { authorization: "Bearer test-token" } })`.

See `examples/calendar-agent` for a complete agent.
