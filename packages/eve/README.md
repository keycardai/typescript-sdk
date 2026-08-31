# @keycardai/eve

> Preview. Keycard auth for [eve](https://eve.dev) agents: a zone token verifier for a channel's auth walk, Keycard-backed connection auth, and interactive authorization over the zone's web flow.

Three adapters, each one plugging into an eve primitive instead of wrapping it:

| Adapter | eve primitive | What it does |
| --- | --- | --- |
| `keycardAuth()` | a channel's ordered `auth` array | Verifies a zone-issued bearer and projects the claims onto `SessionAuthContext`. |
| `Keycard.asSelf()`, `Keycard.onBehalfOf()`, `Keycard.impersonate()` | connection `auth` | Acquires a resource token at the tool-call boundary, for the app or for the turn's current user. |
| `Keycard.interactive()` | `defineInteractiveAuthorization` | Runs the zone's browser authorization flow and lets eve park the turn until the user consents. |

## Installation

```bash
pnpm add @keycardai/eve
```

`eve` is a peer dependency, pinned to `>=0.47.3 <0.48.0`. This package was
built and verified against eve `0.47.3`. eve is in public beta and ships
releases most days, and its connection and auth surfaces are still moving, so
the range deliberately stops at the next minor rather than tracking `^`. Widen
it only after re-running this package's tests against the newer eve.

eve itself declares `engines.node: ">=24"` and is ESM only. This package
imports eve for types only (`import type { ... } from "eve/connections"`), so
nothing here pulls eve into the runtime and the package builds and tests on
Node 22 as the rest of this repository's CI does. It ships an ESM build only,
because an eve app is ESM.

## 1. Verify the caller: `keycardAuth()`

```ts title="agent/channels/eve.ts"
import { eveChannel } from "eve/channels/eve";
import { localDev } from "eve/channels/auth";
import { keycardAuth } from "@keycardai/eve";

export default eveChannel({
  auth: [
    keycardAuth({
      zoneUrl: process.env.KEYCARD_ZONE_URL!,
      audience: "https://agent.example.com",
    }),
    localDev(),
  ],
});
```

Three outcomes, matching eve's ordered walk:

- No bearer, or a bearer this zone did not issue: returns `null`, so the next
  entry in the array still gets a turn.
- A bearer this zone issued that does not verify, has expired, or names another
  audience: throws with a `401` `Response`, which ends the walk. A broken
  Keycard credential is a rejection, not an invitation to fall through to
  something weaker.
- A verified bearer: returns `{ principalId, principalType, attributes, issuer,
  subject }`, and retains the raw token for a later on-behalf-of exchange.

The retained subject token stays out of durable state by default: it lives in a
process-local store keyed by the principal eve projects onto a connection, so
it never reaches the model, the session record, or the event stream. Pass
`retainSubjectToken: "attributes"` when connections run in a different process
from the request that authenticated the caller, which accepts a bearer token in
eve's session attributes in exchange for surviving restarts. Pass `"none"` for
zones whose connections only ever run `asSelf` or `impersonate`.

The verifier and its JWKS keyring are built once per `keycardAuth()` call and
cache discovery and signing keys, so a request pays no discovery round trip.

## 2. Acquire resource tokens: connection auth

```ts title="agent/connections/calendar.ts"
import { defineMcpClientConnection } from "eve/connections";
import { Keycard } from "@keycardai/eve";

export default defineMcpClientConnection({
  url: "https://calendar.example.com/mcp",
  description: "The signed-in user's calendar.",
  auth: Keycard.onBehalfOf({
    zoneUrl: process.env.KEYCARD_ZONE_URL!,
    resource: "https://calendar.example.com",
    requestScopes: ["calendar.read"],
    clientId: process.env.KEYCARD_CLIENT_ID!,
    clientSecret: process.env.KEYCARD_CLIENT_SECRET!,
  }),
});
```

- `Keycard.onBehalfOf()` is user-scoped, so eve resolves the principal from the
  active turn's `ctx.session.auth.current` and rejects with
  `reason: "principal_required"` when there is no authenticated user. It
  exchanges the subject token `keycardAuth()` verified for that same principal.
- `Keycard.asSelf()` is app-scoped and runs client credentials under the
  agent's own identity, so it works on schedules and subagent turns. It never
  performs an exchange, so nothing about a caller reaches the zone.
- `Keycard.impersonate({ userIdentifier })` uses the zone's substitute-user
  exchange for a user the agent holds no token for. A fixed identifier makes
  the connection app-scoped; a function receives the connection principal and
  makes it user-scoped.

Nothing falls back to the agent's authority. A user-pattern connection with no
user principal, a turn whose subject token was never retained, and an expired
subject token all fail, each with its own reason: `principal_required`,
`subject_token_unavailable`, and `subject_token_expired`. The last one is the
sign-in signal, decided by a decode-only expiry check, so an already dead token
never costs an exchange round trip.

Credentials go in as either `clientId` plus `clientSecret` (shorthand for a
client-secret credential) or `applicationCredential` (any
`ApplicationCredential`, including assertion-based workload credentials, whose
`clientAssertion`, `clientAssertionType`, and `clientId` are forwarded). Setting
both is a configuration error.

Every factory builds one warm zone client and reuses it, so tool calls do not
pay per-call discovery or client construction.

### A revoked token mid-call

`getToken` runs before a tool call, so a grant revoked while a tool is in
flight surfaces as a `401` inside `execute`. Map it to `ctx.requireAuth` so eve
evicts the rejected bearer and re-challenges instead of handing the model a
dead-token error:

```ts
import { requireAuthOnUnauthorized } from "@keycardai/eve";

if (!res.ok) requireAuthOnUnauthorized(res, ctx, calendarAuth);
```

## 3. Ask the user to sign in: `Keycard.interactive()`

```ts title="agent/connections/docs.ts"
import { defineMcpClientConnection } from "eve/connections";
import { Keycard } from "@keycardai/eve";

export default defineMcpClientConnection({
  url: "https://docs.example.com/mcp",
  description: "Documents the user has authorized.",
  auth: Keycard.interactive({
    zoneUrl: process.env.KEYCARD_ZONE_URL!,
    clientId: process.env.KEYCARD_CLIENT_ID!,
    resource: "https://docs.example.com",
    requestScopes: ["documents.read"],
  }),
});
```

The definition implements the same three-method form as eve's
`defineInteractiveAuthorization`, over `@keycardai/oauth`'s v3 web-app flow:

- `getToken` returns a token only when this package holds one for the
  principal. Otherwise it throws `ConnectionAuthorizationRequiredError`, so eve
  emits `authorization.required`, runs `startAuthorization` in a durable step,
  and parks the turn on a framework-owned callback.
- `startAuthorization` calls `beginAuthorization` for the connection's resource
  list against eve's minted callback URL, and returns the challenge URL plus
  the `state` and PKCE verifier as JSON resume state.
- `completeAuthorization` calls `completeAuthorization` with eve's callback
  params and the journaled resume state, and hands eve the token.

**Resume without authorization cannot yield a credential.** `getToken` is the
only path that returns a token, and it reads a store only
`completeAuthorization` writes. A denied, forged, or failed callback writes
nothing, so a resumed turn either finds a real grant or throws `Required` again
and parks. eve's own exactly-once settlement makes that terminal instead of a
loop: it settles each parked authorization once, and a `Required` thrown after
an authorization has settled ends the tool call. User denial is reported as
`ConnectionAuthorizationFailedError` with `reason: "access_denied"` and
`retryable: false`, so eve stops re-prompting.

## Parity with `@keycardai/langchain`

The two packages implement the same Keycard access model against different
framework primitives. What LangChain needs middleware and interrupts for, eve
already owns:

| `@keycardai/langchain` | `@keycardai/eve` |
| --- | --- |
| `keycardAccess()` middleware wrapping tool execution | connection `auth` definitions; eve calls `getToken` at the tool boundary and attaches the bearer itself |
| `Access.asSelf()`, `Access.onBehalfOf()`, `Access.impersonate()` | `Keycard.asSelf()`, `Keycard.onBehalfOf()`, `Keycard.impersonate()` |
| LangGraph `interrupt()` for sign-in and consent | eve durable parks driven by `ConnectionAuthorizationRequiredError` and the `authorization.required` event |
| middleware-managed token cache and per-run identity | eve's per-step credential cache and session principal (`ctx.session.auth.current`) |
| middleware keeping credentials out of tool arguments | eve keeping credentials out of the model's view by construction, since auth never appears in a tool's input schema |
| `subjectTokenExpired()` decode-only expiry check | the same check, exported here as well |
| fake zone client from `@keycardai/langchain/testing` | fake zone client from `@keycardai/eve/testing` |

There is no middleware to install here, and no tool wrapper. The package
supplies auth functions and auth definitions, and eve does the rest.

## Testing offline

`@keycardai/eve/testing` provides seams that take no network:

```ts
import { fakeZoneClient, userPrincipal, validJwt } from "@keycardai/eve/testing";
import { Keycard, memorySubjectTokenStore } from "@keycardai/eve";

const client = fakeZoneClient({ failResources: ["https://calendar.example.com"] });
const subjectTokens = memorySubjectTokenStore();
subjectTokens.set("https://zone.example.com|user-1", validJwt(3600));

const auth = Keycard.onBehalfOf({
  resource: "https://calendar.example.com",
  client,
  subjectTokens,
});
```

`fakeZoneClient()` records every exchange, impersonation, and client
credentials call, and can fail one resource or every request. `keycardAuth()`
takes a `verify` seam in place of the JWKS-backed verifier, and
`Keycard.interactive()` takes a `flow` seam in place of the two web-flow calls.
An injected `client` or `flow` supersedes `zoneUrl`, so a test needs no zone.

## Not included: the Keycard gateway MCP proxy

Routing third-party MCP servers through the Keycard gateway is out of scope for
this release, pending svc-sts #651, exactly as in `@keycardai/langchain`.
Third-party MCP servers reached directly through eve's native connections are
supported, and that is what the examples above do.
