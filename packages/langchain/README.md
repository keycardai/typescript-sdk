# @keycardai/langchain

Keycard integration for LangChain agents. Every tool call gets a short-lived
credential brokered by Keycard, scoped to the identity the agent is acting for,
and recorded in the audit log.

Your tools never hold an API key, the model never sees a credential, and you do
not write an OAuth flow.

This is the TypeScript half of a cross-language package. It carries the same
contract as Python's [`keycardai-langchain`](https://pypi.org/project/keycardai-langchain/)
(same concepts, same interrupt payloads, same behavior) spelled the way
TypeScript spells things. The [parity table](#contract-parity-with-python) maps
one to the other.

## Install

```bash
npm install @keycardai/langchain langchain @langchain/core @langchain/langgraph
```

## Quick start

```typescript
import { createAgent } from "langchain";
import { tool } from "@langchain/core/tools";
import { z } from "zod";
import {
  Access,
  getAccessContext,
  keycardGrantMiddleware,
} from "@keycardai/langchain";

const CALENDAR = "https://www.googleapis.com/calendar/v3";

const keycard = keycardGrantMiddleware({
  zoneUrl: "https://your-zone.keycard.cloud",
  resources: [CALENDAR],
  clientId: "your-agent",
  clientSecret: process.env.KEYCARD_CLIENT_SECRET,
});

const listEvents = tool(
  async ({ daysAhead }) => {
    const token = getAccessContext().access(CALENDAR).accessToken;
    // ... call the calendar API with token
  },
  {
    name: "list_events",
    description: "List the user's calendar events.",
    schema: z.object({ daysAhead: z.number().default(0) }),
  },
);

const agent = createAgent({
  model,
  tools: [listEvents],
  middleware: [keycard],
});

await agent.invoke(
  { messages: [{ role: "user", content: "what's on my calendar?" }] },
  { context: Access.onBehalfOf(callerToken) },
);
```

That is the whole integration: one middleware in the agent's middleware list,
and one call inside each tool to read the credential for this call.

## How it works

The middleware implements LangChain's `wrapToolCall` hook, so it runs at the
tool-call boundary. Before each tool executes it acquires tokens for the
declared resources under the identity of the run, then exposes the result to
the tool as an `AccessContext`.

Identity travels on the run's context, and the pause-for-authorization flow is
a LangGraph interrupt. The middleware carries the identity `contextSchema`
itself, so the agent does not have to declare one.

## Access patterns

Identity is per run, not per deployment: one deployed agent serves many
callers. Use an `Access.*` factory to select the pattern:

| Field | Factory | Meaning |
|---|---|---|
| `subjectToken` | `Access.onBehalfOf(...)` | Exchange the caller's own token for resource tokens (RFC 8693). |
| `asSelf: true` | `Access.asSelf()` | Client-credentials grant under the agent's own application identity. No user anywhere. |
| `userIdentifier` | `Access.impersonate(...)` | Substitute-user exchange, authenticated by the agent's credential. Forbidden by default; requires a zone policy. |

A run with no identity fails with a `missing_identity` error, or pauses with a
`sign_in_required` interrupt when `signInUrl` is set. It never falls back to
the agent's own authority: acting as itself is always an explicit choice.

### On-behalf-of: a user-facing agent

The agent acts for the person in the chat. Their token is exchanged per tool
call, so every resource access is attributed to agent-for-user in the audit
log, and revoking the user's grant cuts the agent off immediately.

```typescript
const keycard = keycardGrantMiddleware({
  zoneUrl: "https://your-zone.keycard.cloud",
  resources: [CALENDAR],
  clientId: "your-agent",
  clientSecret: process.env.KEYCARD_CLIENT_SECRET,
  // Optional: pause the run in-chat instead of failing.
  signInUrl: "https://your-app.example/signin",
  authorizationUrl: "https://your-app.example/authorize",
});

await agent.invoke(
  { messages },
  { context: Access.onBehalfOf(callerToken) },
);
```

### As itself: a background agent

No user in the loop: a scheduled digest, a queue worker, a monitor. The agent
authenticates as its own application, and never interrupts: there is no user
to send to a sign-in page.

```typescript
await agent.invoke({ messages }, { context: Access.asSelf() });
```

### Impersonation: acting as a specific user without their token

```typescript
await agent.invoke(
  { messages },
  { context: Access.impersonate("user@example.com") },
);
```

### Authenticating without a static secret

`clientId` / `clientSecret` is shorthand for a `ClientSecret` credential. Every
pattern also accepts an `applicationCredential`, so a deployed agent can
authenticate with a platform-signed token instead of holding a secret:

```typescript
import { ClientSecret } from "@keycardai/oauth";

const keycard = keycardGrantMiddleware({
  zoneUrl: "https://your-zone.keycard.cloud",
  resources: [CALENDAR],
  applicationCredential: new ClientSecret("your-agent", secret),
});
```

Assertion-based credentials work the same way: their proof rides in the request
as a jwt-bearer client assertion, for both the exchange and the as-itself
grant. Pass `applicationCredential` **or** `clientId`/`clientSecret`, never
both.

### Identity without per-run context

For a deployed agent whose surface does not thread per-run context, set
`fallbackIdentity`. Pass a **function** to resolve it per tool call, so a
sign-in that happens mid-conversation takes effect on resume without a restart:

```typescript
const keycard = keycardGrantMiddleware({
  // ...
  fallbackIdentity: () => Access.onBehalfOf(sessionToken()),
});
```

## Serving many callers: per-caller authentication

The patterns above answer "what does this run act as". A deployed agent has a
second question: who is calling. Without an answer, one deployment holds one
identity, so the last caller to sign in acts for everybody.

`@keycardai/langchain/serve` closes that half for a LangGraph JS server. It
verifies each caller's own zone-issued bearer per request, hands the run that
identity plus the raw bearer, and scopes threads, runs and store items to their
owner. The subpath is separate because it imports `@langchain/langgraph-sdk`,
which only a served agent needs:

```bash
npm install @keycardai/langchain @langchain/langgraph-sdk
```

`src/auth.ts` in your app:

```typescript
import { Auth } from "@langchain/langgraph-sdk/auth";
import {
  installOwnerAuthorization,
  zoneAuthenticator,
} from "@keycardai/langchain/serve";

export const auth = installOwnerAuthorization(
  new Auth().authenticate(
    zoneAuthenticator({
      zoneUrl: "https://your-zone.keycard.cloud",
      resource: "https://your-agent.example",
    }),
  ),
);
```

Then point the middleware at the caller the server verified, instead of at
per-run context:

```typescript
const keycard = keycardGrantMiddleware({
  zoneUrl: "https://your-zone.keycard.cloud",
  resources: [CALENDAR],
  identitySource: "auth_user",
});
```

`identitySource: "auth_user"` reads the verified caller from
`config.configurable.langgraph_auth_user`, which the server populates per
request. Nothing in the request body can name an identity, and no identity
state is shared between callers. A run that reaches the middleware without a
verified caller resolves to no identity, which is the usual missing-identity
error or sign-in interrupt. It cannot be combined with `fallbackIdentity`,
since that would let an unauthenticated run act as somebody.

`installOwnerAuthorization` covers what authentication alone does not:
authentication says who is calling but grants no ownership, so without it any
valid caller can read and resume any other caller's thread. It stamps the
verified owner on thread creation, run creation and thread updates (never
taking it from the request body, so an update cannot reassign ownership),
filters reads, searches and deletes by that owner, prefixes store namespaces
in place with a digest of the owner so every store operation, including a
prefixed search, runs inside the caller's own subtree, denies namespace
enumeration without a prefix, denies Studio users, and denies every unmatched
resource and action pair, because LangGraph's authorization handlers otherwise
fail open.

### langgraph.json

```json
{
  "node_version": "20",
  "graphs": { "agent": "./src/graph.ts:graph" },
  "auth": {
    "path": "./src/auth.ts:auth",
    "disable_studio_auth": true
  }
}
```

`disable_studio_auth: true` is required, not optional. With it unset, a request
carrying the `x-auth-scheme: langsmith` header skips your hook entirely and
arrives as the built-in `langgraph-studio-user`, which is an unauthenticated
path into the deployment.

### Operational notes

The JS server runs the authentication hook on everything except `GET /info`,
which serves versions and feature flags without a bearer, and `GET /ui/*`,
which the server skips for UI asset requests (a 404 on `/ui/*` is a route
miss, not a challenge; a deployment that registers generative UI assets serves
them without a bearer). `/ok`, `/docs`, `/openapi.json` and `/metrics` all
require one, so a liveness probe against `/ok` needs a token or should target
`/info`.

Store namespaces are owner-prefixed in place, so a caller's `put`, `get`,
`delete`, `search` and prefixed `list_namespaces` all operate inside their own
subtree with their usual namespaces; results come back with the owner segment
as the first label. Listing namespaces without a prefix is denied (403): the
JS server queries that listing in a way no owner scope can reach, so it is
unsupported rather than unscoped. Find your own data with a scoped search
instead.

Verified identity is request-scoped, so concurrent callers never mix, and the
JS CLI starts ten workers by default, so their runs really do overlap.

Resuming an interrupt re-runs the hook, and the resumed node executes under the
resumer's identity, not the identity that parked it. Thread ownership is what
keeps a resume with its owner, which is another reason
`installOwnerAuthorization` is not optional.

[`docs/langgraph-js-auth-probe.md`](./docs/langgraph-js-auth-probe.md) records
the measurements behind each of these statements, and where the JS runtime
differs from Python's.

## Errors are data, not exceptions

A missing grant is normal operation in a brokered setup, so the `AccessContext`
records failures instead of throwing. Only `access(resource)` throws, and only
when you ask for a resource that has no token:

```typescript
const access = getAccessContext();
if (access.hasErrors()) {
  return `Cannot reach the API yet: ${JSON.stringify(access.getErrors())}`;
}
const token = access.access(CALENDAR).accessToken;
```

Returning a readable sentence beats throwing here: in a chat UI a thrown error
reads as an internal error, when the truthful message is "you have not granted
this yet."

Acquisition is per resource, so a denied resource never poisons the granted
ones: `getResourceError(resource)` reports the one that failed while the others
keep serving tokens.

## Pausing for sign-in and consent

With `signInUrl` and `authorizationUrl` set, the middleware pauses the run with
a LangGraph interrupt instead of failing, so the whole flow can live in your
chat surface:

```typescript
const keycard = keycardGrantMiddleware({
  zoneUrl: "https://your-zone.keycard.cloud",
  resources: [CALENDAR],
  signInUrl: "https://your-app.example/signin",
  authorizationUrl: (resources) =>
    `https://your-app.example/authorize?r=${encodeURIComponent(resources[0])}`,
});
```

| Payload `type` | Fires when | Resume behavior |
|---|---|---|
| `sign_in_required` | The run carries no identity, or its subject token has expired | Identity is re-resolved, then the exchange runs |
| `authorization_required` | Identity present and valid, grant missing | The exchange is retried |

The payloads are the contract, so they keep their wire spelling in TypeScript
too:

```typescript
{ type: "sign_in_required", sign_in_url, reason, message }
{ type: "authorization_required", authorization_url, resources, errors, message }
```

Expiry is detected locally (a decode-only check of the JWT's `exp`; the zone
stays the authority on validity), so an expired session routes to sign-in
rather than to a consent page that cannot fix it. The `sign_in_required`
payload carries a `reason` field (`missing_identity` or
`subject_token_expired`) so a chat surface can word the prompt accordingly.

Both require a checkpointer, unless you switch delivery to tool output with
[`interruptOnAuth: false`](#without-a-checkpointer-interruptonauth-false). Three
details worth knowing:

- **Resume needs no new token.** Consent changes the grant in the zone, not the
  token in your session, so the existing subject token exchanges successfully
  afterward.
- **Runtime context is not checkpointed.** A resume must re-supply identity,
  which a server does on every run anyway.
- **A premature resume re-interrupts.** Resuming without authorizing retries
  acquisition and pauses again, up to three attempts per tool call, rather than
  letting an unauthorized call through. After the cap the failure stays on the
  access context as an error the tool reads.

Scope granularity falls out of this for free: if a user has granted read but
not write, the read call succeeds and the write call is the one that pauses.

### Without a checkpointer: `interruptOnAuth: false`

Deployments that keep no graph state have nothing to resume, so the interrupt is
not available to them. Set `interruptOnAuth: false` and the same failure is
delivered to the model as failed tool output instead of pausing the run:

```typescript
const keycard = keycardGrantMiddleware({
  zoneUrl: "https://your-zone.keycard.cloud",
  resources: [CALENDAR],
  signInUrl: "https://your-app.example/signin",
  authorizationUrl: (resources) =>
    `https://your-app.example/authorize?r=${encodeURIComponent(resources[0])}`,
  interruptOnAuth: false, // no checkpointer needed
});
```

The tool output carries the same kind, reason and URL the interrupt payload
would, worded so the model relays the URL to the user verbatim rather than
paraphrasing it. The wrapped tool does not run, so the never-fall-back
guarantee holds exactly as on the interrupt path. The run finishes normally,
with the link in the assistant's reply; the user authorizes out of band, and
their next turn retries the tool, which now succeeds. Nothing resumes mid-run,
so there is no bounded retry loop here.

Reach for it when your agent is stateless (a plain HTTP handler, a queue worker,
a Slack or email surface with no persisted thread), or when the auth step
belongs in the conversation instead of in a paused-run UI. Keep the default when
you run with a checkpointer: a pause is stricter, since the model never gets a
turn between the failure and the retry.

Python's `interrupt_on_auth=False` renders the same payload, so the two
middlewares behave identically here.

## Using tools outside the agent

`getAccessContext()` normally only works inside an agent run, because the
middleware installs the context at the tool-call boundary. For code that calls
a tool without the agent loop, `grant()` enters the same access context
explicitly. The motivating case is a UI panel served by the same governed tool
the agent uses in chat:

```typescript
const snapshot = await keycard.grant(
  { identity: Access.onBehalfOf(sessionToken) },
  () => listRequests.invoke({}),
);
```

It also serves resources that have no tool at all. Fetching a vaulted LLM key
under the agent's own identity, for example:

```typescript
const key = await keycard.grant(
  { identity: Access.asSelf(), resources: [LLM_KEY] },
  (access) => access.access(LLM_KEY).accessToken,
);
```

`grant` takes `toolName` to apply that tool's `toolResources` override, or
`resources` to grant exactly the listed resources (one or the other, not both),
and falls back to `fallbackIdentity` when no identity is passed. There is no
run to pause, so nothing interrupts here: failures stay on the access context,
exactly as tools see them.

## Per-tool resources and scopes

```typescript
keycardGrantMiddleware({
  zoneUrl: "https://your-zone.keycard.cloud",
  resources: [CALENDAR],                    // default for every tool
  toolResources: { post_message: [SLACK] }, // per-tool override
  requestScopes: { [CALENDAR]: ["calendar.events"] },
});
```

A tool absent from `toolResources` gets `resources`; an empty array means the
middleware exchanges nothing for that tool.

`requestScopes` is the **outbound** scope requested from Keycard, for both the
exchange and the as-itself grant. It is distinct from any scope enforced on the
caller's inbound token.

## The hot path

The middleware builds one zone client and keeps it: the underlying
`@keycardai/oauth` clients cache the zone's token endpoint after their first
call, so a tool call pays neither client construction nor rediscovery. Create
the middleware once at module scope and share it across runs and users;
identity rides the run, not the middleware.

## Testing

Tool tests need no zone and no network:

```typescript
import { mockAccessContext } from "@keycardai/langchain/testing";

it("lists events", async () => {
  await mockAccessContext({ resourceTokens: { [CALENDAR]: "test-token" } }, () =>
    listEvents.invoke({ daysAhead: 0 }),
  );
});
```

`mockAccessContext({ accessToken })` serves one token for any resource, which is
convenient but cannot catch a mistyped resource URL, since every lookup
succeeds. Pass `resourceTokens` when the test should assert which resource a
tool reads. `resourceErrors` and `errorMessage` cover the failure paths, and
`overrideAccessContext` takes a hand-built `AccessContext` for full control.

## Contract parity with Python

Same contract, idiomatic expression on each side. Concepts, payload shapes,
defaults, and behaviors are identical; the spelling follows each language.

| Concept | Python (`keycardai-langchain`) | TypeScript (`@keycardai/langchain`) |
|---|---|---|
| Middleware | `KeycardGrantMiddleware(...)` | `keycardGrantMiddleware({ ... })` |
| Identity type | `KeycardIdentity` (dataclass, passed as `context_schema`) | `KeycardIdentity` / `keycardIdentitySchema` (carried by the middleware) |
| Identity factories | `Access.as_self()`, `Access.on_behalf_of(token)`, `Access.impersonate(user)` | `Access.asSelf()`, `Access.onBehalfOf(token)`, `Access.impersonate(user)` |
| Access context accessor | `get_access_context()` | `getAccessContext()` |
| Zone | `zone_url=` | `zoneUrl:` |
| Resource configuration | `resources=`, `tool_resources={tool: [...]}` | `resources:`, `toolResources: { tool: [...] }` |
| Outbound scopes | `request_scopes=` | `requestScopes:` |
| Credential | `application_credential=`, or `client_id=` / `client_secret=` | `applicationCredential:`, or `clientId:` / `clientSecret:` |
| Sign-in URL | `sign_in_url=` | `signInUrl:` |
| Authorization URL | `authorization_url=` (str or callable) | `authorizationUrl:` (string or function) |
| Fallback identity | `fallback_identity=` (value or callable) | `fallbackIdentity:` (value or function) |
| Escape hatch | `with keycard.grant(...) as access:` / `async with keycard.agrant(...)` | `await keycard.grant(options, (access) => ...)` |
| Testing seam | `mock_access_context(...)`, `override_access_context(...)` | `mockAccessContext(...)`, `overrideAccessContext(...)` |
| Error accessors | `has_errors()`, `get_errors()`, `get_resource_error(r)` | `hasErrors()`, `getErrors()`, `getResourceError(r)` |
| Ungranted read | raises `ResourceAccessError` | throws `ResourceAccessError` |
| Interrupt payloads | `sign_in_required` / `authorization_required`, snake_case fields | identical, snake_case fields preserved |
| Attempt cap | 3 acquisition attempts per tool call | 3 acquisition attempts per tool call |
| Checkpointer-less delivery | `interrupt_on_auth=` (default `True`) | `interruptOnAuth:` (default `true`) |
| Served-agent authenticate | `zone_authenticator(zone_url=, resource=)` | `zoneAuthenticator({ zoneUrl, resource })` |
| Served-agent ownership | `install_owner_authorization(auth)` | `installOwnerAuthorization(auth)` |
| Served-agent identity mode | `identity_source="auth_user"` | `identitySource: "auth_user"` |
| Served-agent import | `keycardai.langchain.auth` (`serve` extra) | `@keycardai/langchain/serve` subpath |

Deliberate differences, where the language leaves no honest choice:

- **The escape hatch is a callback, not a context manager.** TypeScript has no
  `with`, and an async-scoped context must close over the body to be removed
  reliably, so `grant` takes the body as a function. It is always `await`ed,
  which is why there is no separate `agrant`: the sync/async split that
  `grant`/`agrant` answers in Python does not exist here.
- **The middleware owns the context schema.** Python passes
  `context_schema=KeycardIdentity` to `create_agent`; the JS middleware
  declares `contextSchema` itself, which is how LangChain 1.x middleware
  contributes context.
- **`Access` is a namespace of factories, not a class.** It cannot be
  constructed on either side; TypeScript expresses that as a frozen object
  rather than a class with a private constructor.
- **Rejections use the LangGraph SDK's own `HTTPException`.** Python has to
  raise Starlette's, because the Python SDK exception drops headers and coerces
  statuses. The JS server preserves the status and headers of the SDK
  exception, so the `WWW-Authenticate` challenge survives without reaching past
  the SDK.
- **The unauthenticated surface is two routes, not seven.** Python serves
  `/ok`, `/info`, `/docs`, `/openapi.json`, `/metrics`, `GET /ui/*` and
  `/noauth*` without the hook; the JS server runs the hook on all of them
  except `GET /info` and `GET /ui/*`.
- **Namespace enumeration without a prefix is denied, not scoped.** Both
  runtimes hand the store handler a mutable namespace, and on both the owner
  segment is prepended so queries run inside the caller's subtree. But the JS
  server queries a prefix-less `list_namespaces` without reading the mutated
  value back, and its only filter operator for namespaces matches labels by
  containment, which caller-chosen labels can forge. Python scopes that
  listing; the JS package fails closed and denies it.

## Not in this package

The middleware brokers credentials for tools that call APIs directly. MCP
servers that run their own interactive OAuth are `@keycardai/mcp`'s concern;
this package has no MCP dependency. A Keycard gateway MCP proxy rides the plain
exchange path here, like any other resource.
