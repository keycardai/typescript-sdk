# LangGraph JS custom auth: probe findings

Empirical probe of the JavaScript LangGraph server's custom auth seam, run
before this package's served-auth surface was written. It repeats the method of
the Python probe (`keycard-sandbox/langchain-fly-demo`,
`docs/langgraph-auth-probe.md`) against a different codebase, so none of the
Python conclusions are assumed here. Verdict: safe to build on, with the
caveats below closed, and with four behaviors that differ from Python.

Probed on a scratch app under `langgraph dev`, stub verifier, no network and no
OAuth: bearer `token-a` resolves to `user-a`, `token-b` to `user-b`, anything
else is rejected. Installed versions, from `npm ls`, on Sep 1, 2026:

```text
@langchain/langgraph       1.4.13
@langchain/langgraph-sdk   1.10.0
@langchain/langgraph-cli   1.4.5
@langchain/langgraph-api   1.4.5
@langchain/core            1.2.9
```

`GET /info` on the running server reports the same pair:

```json
{"version":"1.4.5","langgraph_js_version":"1.4.13","context":"js","flags":{"assistants":true,"crons":false,"langsmith":false,"langsmith_tracing_replicas":true}}
```

## 1. Coverage: what runs without the hook

With no `Authorization` header at all, so a 401 means the hook ran and
rejected:

```text
GET    /ok                                -> 401
GET    /info                              -> 200
GET    /docs                              -> 401
GET    /openapi.json                      -> 401
GET    /metrics                           -> 401
GET    /ui/anything                       -> 404
GET    /noauth                            -> 401
GET    /noauth/anything                   -> 401
GET    /assistants/agent/schemas          -> 401
POST   /assistants/search                 -> 401
POST   /threads                           -> 401
POST   /threads/search                    -> 401
POST   /runs/wait                         -> 401
POST   /runs/stream                       -> 401
POST   /store/items/search                -> 401
PUT    /store/items                       -> 401
```

The same two routes with a valid bearer:

```text
/ok                                -> 200
/threads                           -> 200
```

`GET /info` is the only unauthenticated route, and it exposes versions and
feature flags only.

Implication: the hook covers the whole surface a caller can reach, including
health, docs and the OpenAPI document, so a client that probes `/ok` for
liveness needs a bearer.

Difference from Python: Python leaves `/ok`, `/info`, `/docs`,
`/openapi.json`, `/metrics`, `GET /ui/*` and any `/noauth*` path
unauthenticated. JS authenticates all of them except `/info`.

## 2. Rejection shape: what survives to the response

A missing bearer, with the hook throwing the SDK's `HTTPException` carrying a
`WWW-Authenticate` header:

```text
$ curl -s -i -X POST localhost:2026/threads -H 'content-type: application/json' -d '{}'
HTTP/1.1 401 Unauthorized
content-type: text/plain;charset=UTF-8
www-authenticate: Bearer error="invalid_request", error_description="A bearer token is required", authorization_uri="https://zone.example/.well-known/oauth-authorization-server"
content-length: 26

A bearer token is required
```

Probing what the framework preserves, by throwing different shapes from the
hook:

```text
Bearer probe-teapot       -> 418, www-authenticate: Bearer error="teapot", x-probe: kept
Bearer probe-403          -> 403, www-authenticate: Bearer error="insufficient_scope"
Bearer probe-bare-object  -> 401, www-authenticate: Bearer error="bare"
Bearer probe-plain-error  -> 500, no www-authenticate
```

The server's conversion, in `@langchain/langgraph-api/dist/auth/index.mjs`,
rethrows anything with a numeric `status` and a `headers` property as a hono
`HTTPException` whose `res` carries that status and those headers, and rethrows
everything else untouched, which the request handler turns into a 500.

Implication: throw the SDK's `HTTPException` with explicit `headers`, and catch
every unexpected error inside the hook so it cannot leave as a 500 with no
challenge.

Difference from Python: in Python the SDK's own `Auth.exceptions.HTTPException`
drops headers and coerces statuses, so the challenge has to be raised as
`starlette.exceptions.HTTPException`. In JS the SDK exception is the correct
one, and no arbitrary status is coerced.

## 3. Identity delivery: which key carries the user

A run with a valid bearer, printing what the node sees on its config:

```text
$ curl -s -X POST localhost:2026/runs/wait -H 'authorization: Bearer token-a' \
    -H 'content-type: application/json' \
    -d '{"assistant_id":"agent","input":{"messages":[{"type":"human","content":"hi"}]}}'
{"identity":"user-a","subject_token":"token-a","kind":null,
 "user_keys":["display_name","identity","is_authenticated","permissions","subject_token"],
 "user_type":"Object",
 "configurable_auth_keys":["langgraph_auth_permissions","langgraph_auth_user","langgraph_auth_user_id","user-agent","user_id"]}
```

The user arrives as a plain object at
`config.configurable.langgraph_auth_user`, alongside
`langgraph_auth_user_id`, `user_id` and `langgraph_auth_permissions`. The
extra `subject_token` key the hook returned survives normalization, which adds
`is_authenticated` and defaults `display_name` to the identity. Inside agent
middleware the same object is reachable as
`request.runtime.configurable.langgraph_auth_user`; `request.runtime.context`
stays separate and empty.

Implication: the raw bearer can ride to the run as an extra key on the user,
which is the only per-request channel the exchange has, and a caller cannot
put anything there from the request body.

Same as Python, except that the JS user is a plain object rather than Python's
`ProxyUser`, so fields are read as properties and not attributes.

## 4. Concurrency: two callers in flight

Two runs launched simultaneously, one per bearer, with a three second sleep in
the node so they overlap:

```text
[whoami:enter] {"identity":"user-a","subject_token":"token-a",...}
[whoami:enter] {"identity":"user-b","subject_token":"token-b",...}
[whoami:exit]  {"identity":"user-a","subject_token":"token-a",...}
[whoami:exit]  {"identity":"user-b","subject_token":"token-b",...}
out-a.json -> user-a
out-b.json -> user-b
```

Implication: identity is request scoped, and a single deployment serves two
callers concurrently with no cross-talk.

Difference from Python: real overlap needed no flag here. The Python CLI
serializes runs at its default `--n-jobs-per-worker 1`; the JS CLI starts ten
workers by default (`Starting 10 workers` in its own startup log).

## 5. Authorization handlers: precedence and fail-open

The probe app deliberately registered only `threads:create`, then exercised
pairs no handler covers:

```text
POST /threads              (threads:create)      -> 200, metadata.owner stamped
GET  /threads/{id}         (threads:read)        -> 200 for the other caller
POST /threads/{id}/runs    (threads:create_run)  -> 200 for the other caller
PUT  /store/items          (store:put)           -> 204 for any caller
POST /assistants           (assistants:create)   -> 200
```

`authorize` in `@langchain/langgraph-api/dist/auth/index.mjs` resolves one
handler in the order `resource:action`, `resource`, `*:action`, `*`, and when
none matches it returns `{ filters: undefined }`, which allows the request.

Implication: authentication grants no ownership. Owner stamping, owner filters
and a catch-all `*` handler that denies are part of the minimum viable change,
not a follow-up.

Same as Python.

## 6. Resume: whose identity runs the node

A thread parked on an interrupt by `token-a`, resumed by `token-b`, with no
owner handler on `threads:create_run`:

```text
$ curl -s -X POST localhost:2026/threads/$T/runs/wait -H 'authorization: Bearer token-b' \
    -H 'content-type: application/json' -d '{"assistant_id":"parker","command":{"resume":"resumed-by-b"}}'
{"parked_as":"user-b","resumed_as":"user-b","answer":"resumed-by-b"}
```

The hook re-runs on resume and the node re-executes under the resumer's
identity. With owner stamping and filters installed, the same resume is
rejected before it reaches the graph, and the owner's own resume proceeds:

```text
user-b resumes user-a's parked thread -> HTTP/1.1 404 Not Found
user-a resumes own parked thread      -> resumed_as: user-a
```

Implication: interrupt resumption is not identity continuous, so thread
ownership is what keeps a resume under the identity that parked it.

Same as Python.

## 7. Studio bypass: the sharpest edge

On the default config, with `auth.path` set and nothing else, a request
carrying `x-auth-scheme: langsmith` skips the hook entirely:

```text
$ curl -s -X POST localhost:2026/runs/wait -H 'x-auth-scheme: langsmith' \
    -H 'content-type: application/json' \
    -d '{"assistant_id":"agent","input":{"messages":[{"type":"human","content":"hi"}]}}'
{"identity":"langgraph-studio-user","subject_token":null,"kind":"StudioUser",
 "user_keys":["display_name","identity","is_authenticated","kind","permissions"],
 "configurable_auth_keys":[...,"x-auth-scheme"]}
```

A bogus bearer alongside that header changes nothing; the header wins. Adding
the flag closes it:

```json
{
  "auth": {
    "path": "./src/auth.mts:auth",
    "disable_studio_auth": true
  }
}
```

```text
studio header against the disable_studio_auth server -> 401
```

Implication: set `disable_studio_auth` from day one, and treat
`isStudioUser(user)` as deny in the authorization handlers, since a Studio user
carries no verified bearer and therefore no delegation chain.

Same as Python, including the exact header and the identity string.

## 8. Store payloads: where the namespace lives

The store auth events carry the namespace under a single `namespace` key, but
the HTTP payloads behind them do not: `store:list_namespaces` arrives from a
request field named `prefix`, and `store:search` from `namespace_prefix`. Put,
get and delete operate on the mutated value, so rewriting `value.namespace`
scopes them; search and namespace listing are scoped by the returned filter
instead. Both halves are needed, confirmed against a running server:

```text
put by user-a            -> 204
get by user-a            -> namespace ["fc95297aa4f56781","notes"]
get by user-b            -> null
search by user-b         -> {"items":[]}
search by user-a         -> user-a item only
list_namespaces by user-b (no prefix) -> {"namespaces":[]}
list_namespaces by user-a (no prefix) -> owner-prefixed namespace only
```

Implication: a store handler must both rewrite the namespace and return a
namespace filter, and it must inject the owner segment even when the request
carries no namespace at all.

Same as Python, where `namespace_prefix` is the field the search payload
carries.

## Build consequences for this package

- `zoneAuthenticator` throws the SDK's `HTTPException` with an explicit
  `WWW-Authenticate` challenge, and converts any unexpected verifier failure
  into the same controlled 401.
- `installOwnerAuthorization` stamps owners on `threads:create` and
  `threads:create_run`, filters the `threads` resource, rewrites and filters
  store namespaces with a sha256-derived dot-free owner segment, allows
  assistant reads and searches, denies Studio users, and ends with a `*`
  handler that denies, because dispatch fails open.
- The middleware's `identitySource: "auth_user"` reads
  `configurable.langgraph_auth_user`, taking identity and subject token only
  from the verified caller.
- `langgraph.json` must carry `"disable_studio_auth": true`.
