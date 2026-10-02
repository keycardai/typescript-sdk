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

`eve` is a peer dependency, pinned to `>=0.54.3 <0.55.0`. This package was
built and verified against eve `0.54.3`. eve is in public beta and ships
releases most days, and its connection and auth surfaces are still moving, so
the range deliberately stops at the next minor rather than tracking `^`. Widen
it only after re-running this package's tests against the newer eve.

The narrowness is the point rather than an oversight, and so is keeping the
range current: a consumer who runs a newer eve and installs this anyway —
`--legacy-peer-deps` — silently loses the check, and the incompatibilities
surface at build time instead. Two of them are what the 0.47 → 0.54 bump had to
fix: an `auth` key list that `displayName` is not in, and a `requireAuth`
options type with no `reason` field.

The one runtime dependency besides `@keycardai/oauth` is `@vercel/oidc`, for
the default credential. It is imported on first use, so an agent that passes
its own credential never loads it.

Every zone URL option (`zoneUrl` on `keycardAuth()` and on each factory)
defaults to the `KEYCARD_ZONE_URL` environment variable.

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
    keycardAuth({ audience: "https://agent.example.com" }),
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
    resource: "https://calendar.example.com",
    requestScopes: ["calendar.read"],
  }),
});
```

That is the whole configuration on Vercel. The zone URL comes from
`KEYCARD_ZONE_URL`, and the agent authenticates to the zone with the
deployment's Vercel OIDC token (see [Deploying on Vercel](#deploying-on-vercel)).

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
  makes it user-scoped. See
  [Act for a user without a sign-in per process](#act-for-a-user-without-a-sign-in-per-process).

Nothing falls back to the agent's authority. A user-pattern connection with no
user principal, a turn whose subject token was never retained, and an expired
subject token all fail, each with its own reason: `principal_required`,
`subject_token_unavailable`, and `subject_token_expired`. The last one is the
sign-in signal, decided by a decode-only expiry check, so an already dead token
never costs an exchange round trip.

### Deploying on Vercel

With no credential configured, every factory authenticates to the zone with
`vercelWorkloadIdentity()`: the deployment's Vercel OIDC token, read fresh on
each request and sent as a jwt-bearer client assertion. The agent holds no
client secret, and nothing it holds outlives the request.

1. Enable OIDC federation on the Vercel project (Settings → Security).
2. In the zone, give the application a token credential that trusts Vercel's
   OIDC issuer for the project's subject, for example
   `owner:<team>:project:<project>:environment:*`. The `environment:*`
   wildcard is what lets `eve dev` authenticate as well as production.
3. Set `KEYCARD_ZONE_URL` to `https://<zone-id>.keycard.cloud`.
4. Locally, run `vercel env pull` to write `VERCEL_OIDC_TOKEN` into
   `.env.local`. An expired token is refreshed through the Vercel CLI.

A credential the zone resolves by ID rather than by OIDC subject needs it
named: `applicationCredential: vercelWorkloadIdentity({ clientId })`.

When the token is unavailable, the tool call fails with
`reason: "workload_identity_unavailable"` and a message naming these steps.
It never falls back to another credential.

On another host, pass a credential explicitly. Use `clientId` plus
`clientSecret` (shorthand for a client-secret credential), or
`applicationCredential` (any `ApplicationCredential`, including other
workload credentials, whose `clientAssertion`, `clientAssertionType`, and
`clientId` are forwarded). Setting both is a configuration error. An injected
`client` brings its own authentication and gets no default.

Every factory builds one warm zone client and reuses it, so tool calls do not
pay per-call discovery or client construction.

### Act for a user without a sign-in per process

`Keycard.interactive()` keeps a user's grant in the agent, so where the agent
runs decides how long the grant lives. `Keycard.impersonate()` keeps nothing:
the grant lives in the zone, created once by the user with
`keycard auth resource`, and every tool call asks the zone for a fresh token
for that user. A cold start costs one token request, not a sign-in, and no
refresh token is ever at rest in the agent or its store.

This is typically what "on behalf of a Slack (or other channel) user" means.
The channel tells the agent who is asking, for example a Slack user id the
agent resolves to an email, and the agent names that user to the zone. The
user never signs in to Keycard on the channel. When the caller does carry a
Keycard token, verified by `keycardAuth()`, use `Keycard.onBehalfOf()`
instead, which exchanges that token.

The application proves who it is on each request with its Vercel OIDC token,
so the agent holds no secret either:

```ts title="agent/connections/notion.ts"
import { defineMcpClientConnection } from "eve/connections";
import { Keycard } from "@keycardai/eve";

export default defineMcpClientConnection({
  url: "https://mcp.notion.com/mcp",
  description: "The owner's Notion workspace.",
  auth: Keycard.impersonate({
    resource: "https://mcp.notion.com/mcp",
    // Who the caller is: may be async, e.g. a Slack user id resolved to an email.
    userIdentifier: async (principal) => emailForPrincipal(principal),
    // Who a schedule acts for, since a scheduled turn has no caller.
    unattendedUserIdentifier: "owner@example.com",
    // Locally, `keycard run` has already brokered this token from keycard.toml.
    localTokenEnv: "NOTION_MCP_TOKEN",
  }),
});
```

- `userIdentifier` as a function makes the connection user-scoped. It
  receives the connection principal and may return a promise. Throw from it to
  refuse a caller before any token is requested.
- `unattendedUserIdentifier` (a string, or a function returning one) returns a
  connection `auth` resolver instead of a definition. A turn whose current
  auth is a user acts for `userIdentifier(principal)`. Every other turn, such
  as a schedule, is app-scoped and acts for this identifier. Without it, a
  schedule reaching a user-scoped connection fails with `principal_required`.
- `unattendedUserIdentifier: null`, or a function returning `null`, makes
  those unattended turns act as the agent itself, by client credentials as
  `Keycard.asSelf()` does. A function can decide per run, for example acting
  for a configured user when one is set and as the agent otherwise. A user
  turn never gets the agent's authority: an empty `userIdentifier` is refused
  with `principal_required`.
- `localTokenEnv` names an environment variable that, when set, is returned
  without contacting the zone. It is meant for `keycard run -- eve dev`. Leave
  it unset in deployed environments, because the token is served to every
  principal of the connection. `asSelf` accepts it too.

Impersonation is gated by the zone's policy for the application, so the
policy, not this code, decides whom the agent may act for. Keep a check in
`userIdentifier` as well when the agent should serve only some users.

Two failures are ones a user can fix, and each has its own `reason` and a
message written to be relayed as is:

| `reason` | Cause | Fix |
| --- | --- | --- |
| `user_authorization_required` | The user has not authorized the resource. From `asSelf`, the resource accepts only per-user grants. | `keycard auth resource <resource> --zone <id>`, or the `authorizationHint` you pass when the grant spans more resources (an MCP server that exchanges for an upstream provider's token). |
| `unknown_user` | The identifier is not a user in the zone. | Make the identifier match a zone user exactly. No grant fixes this one. |

A third, `workload_identity_unavailable`, is a deployment fault rather than a
user's (see [Deploying on Vercel](#deploying-on-vercel)). Everything else stays
`acquisition_failed` and carries the zone's message.

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
    resource: "https://docs.example.com",
    requestScopes: ["documents.read"],
    connectionName: "Docs",
  }),
});
```

**There is no `clientId`, and adding one usually breaks the flow.** eve mints a
fresh callback URL for every attempt
(`/eve/v1/connections/:name/callback/:attemptId/:token`) while
[RFC 9700][rfc9700] requires the authorization server to match `redirect_uri`
against the client's registered list by exact string comparison. A client
registered ahead of time cannot name a URL that is generated later, so the
request is rejected with something like `Unauthorized redirect URI`. Leaving
`clientId` unset registers a client per attempt instead (RFC 7591), whose
single redirect URI is the callback that attempt will return to. Each client is
public and PKCE-bound, so nothing secret enters eve's durable resume state; if
the server issues a confidential client anyway, the attempt is abandoned rather
than journaling a secret.

Set `clientId` only when that client's registered redirect URIs already cover
eve's callback. Note that a Keycard application `identifier` is not a client id:
zones identify clients by [Client ID Metadata Document][cimd], an HTTPS URL
with a path serving the client's metadata, so a value like `urn:app:my-agent`
fails with `Unsupported client identifier prefix: urn`.

Per-attempt clients accumulate in the zone. They hold no secret and their
callback is single-use, but a server returning `registration_client_uri` and
`registration_access_token` allows RFC 7592 deletion once a grant settles.

[rfc9700]: https://datatracker.ietf.org/doc/html/rfc9700
[cimd]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02

The definition implements the same three-method form as eve's
`defineInteractiveAuthorization`, over `@keycardai/oauth`'s v3 web-app flow:

- `getToken` looks up the principal's stored grants and returns the access
  token of one whose resources cover this connection's `resource` and whose
  scopes cover `requestScopes`. Within 60 seconds of expiry, a grant holding a
  refresh token is refreshed first (see below). With no usable grant it throws
  `ConnectionAuthorizationRequiredError`, so eve emits
  `authorization.required`, runs `startAuthorization` in a durable step, and
  parks the turn on a framework-owned callback.
- `startAuthorization` registers this attempt's client (unless `clientId` is
  set), calls `beginAuthorization` for the connection's resource list against
  eve's minted callback URL, and returns the challenge URL plus the `state`,
  PKCE verifier and client id as JSON resume state.
- `completeAuthorization` calls `completeAuthorization` with eve's callback
  params and the journaled resume state, redeeming as the client that attempt's
  authorization request ran as, and stores the resulting grant.

**Resume without authorization cannot yield a credential.** `getToken` is the
only path that returns a token, and it reads a store only
`completeAuthorization` writes. A denied, forged, or failed callback writes
nothing, so a resumed turn either finds a real grant or throws `Required` again
and parks. eve's own exactly-once settlement makes that terminal instead of a
loop: it settles each parked authorization once, and a `Required` thrown after
an authorization has settled ends the tool call. User denial is reported as
`ConnectionAuthorizationFailedError` with `reason: "access_denied"` and
`retryable: false`, so eve stops re-prompting.

### Grants: what is stored, and for how long

Only `Keycard.interactive()` stores grants. `impersonate()` and `asSelf()`
store nothing in the agent, and `onBehalfOf()` keeps only the caller's
inbound Keycard token, in memory by default, for the exchange. The deployment
path makes no difference: the Vercel OIDC credential authenticates the agent,
and `interactive()` does not use it.

`completeAuthorization` stores a grant, not a bare token: the access token and
its expiry, the refresh token the zone returned, the client id the grant was
issued to, and the resources and scopes granted. Grants are keyed by the
principal, never by `connectionName`, which is display and error text only;
two `Keycard.interactive()` definitions in one process with the same
`connectionName` fail at definition time with
`AuthProviderConfigurationError`. Because a grant is matched on what it covers,
a connection listing the agent's other resources in `additionalResources`
yields one sign-in that serves every connection whose resource is in the list.

When a grant is within 60 seconds of expiry and holds a refresh token,
`getToken` posts `grant_type=refresh_token` to the zone as the grant's own
client (public, no secret; a per-attempt client registers with
`refresh_token` among its grant types), stores the rotated access and refresh
token pair, and returns the new access token without parking. A refresh the
zone refuses with `invalid_grant` deletes the grant and throws `Required`, so
the turn parks for a fresh sign-in. A transport or 5xx failure keeps the grant
and fails the tool call with `retryable: true`. A grant without a refresh token
parks at expiry, as before.

`evict` removes every grant of the principal that covers this connection's
resource, leaving grants for other resources in place.

### Plugging a durable grant store

The default store is process-local, so a restarted agent parks once more for
each user. To keep grants across processes, pass `tokens` an object of this
shape:

```ts
import type { AuthorizedGrant, GrantStore } from "@keycardai/eve";

export function redisGrantStore(redis: {
  hgetall(key: string): Promise<Record<string, string>>;
  hset(key: string, field: string, value: string): Promise<unknown>;
  hdel(key: string, field: string): Promise<unknown>;
}): GrantStore {
  const key = (principal: string) => `keycard:grants:${principal}`;
  return {
    async list(principal) {
      const rows = await redis.hgetall(key(principal));
      return Object.values(rows).map((row) => JSON.parse(row) as AuthorizedGrant);
    },
    async put(principal, grant) {
      await redis.hset(key(principal), grant.id, JSON.stringify(grant));
    },
    async remove(principal, grantId) {
      await redis.hdel(key(principal), grantId);
    },
  };
}
```

Every method is async, and `put` with an `id` already held replaces that grant
(a refresh rewrites the rotated pair under the same `id`). The same three
methods map onto Upstash Redis's `hgetall`, `hset` and `hdel`, or any other
key-value backend.

Choosing a durable store puts refresh tokens at rest in that backend. Each one
is a long-lived credential for the user's resources, so the backend's access
control and encryption are yours to provide. This package never writes a grant
into eve's session attributes for that reason: a refresh token must not enter
eve's durable state.

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

const client = fakeZoneClient({
  failResources: { "https://calendar.example.com": new Error("exchange refused") },
});
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
`Keycard.interactive()` takes a `flow` seam in place of the web-flow calls:
`begin`, `complete`, `register` for per-attempt clients, and `refresh`. A flow
without `register` is rejected at construction unless a `clientId` is also
given, so a test cannot accidentally exercise a combination that cannot work in
production. An injected `client` or `flow` supersedes `zoneUrl`, so a test needs
no zone.

## Not included: the Keycard gateway MCP proxy

Routing third-party MCP servers through the Keycard gateway is out of scope for
this release, pending svc-sts #651, exactly as in `@keycardai/langchain`.
Third-party MCP servers reached directly through eve's native connections are
supported, and that is what the examples above do.
