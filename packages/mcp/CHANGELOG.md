## 0.11.0-keycardai-mcp (2026-07-06)


- feat(mcp): accept redirect URL and stores via BaseOAuthClientProvider options
- BaseOAuthClientProvider could not be used for the authorization-code flow
without forking: the redirect URL had no constructor parameter and no
setter, so the redirectUrl getter always threw, and the token and code
verifier stores were only injectable by subclassing. An optional options
argument now wires redirectUrl, tokensStore, codeVerifierStore, and
privateKeyring at construction.
- Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>

## 0.10.2-keycardai-mcp (2026-07-02)


- refactor(mcp): vendor server-side auth types, make @modelcontextprotocol/sdk peer optional
- Every @modelcontextprotocol/sdk import in this package is type-only;
the compiled JS has zero runtime references. The official SDK's v2
renames packages, which breaks .d.ts type resolution for v2 adopters
and makes the ^1.15.0 peer range unsatisfiable.
- Vendor structurally identical AuthInfo, OAuthTokenVerifier, and
OAuthProtectedResourceMetadata types in shared/auth and switch the
server-path modules (and the client JWT signer) to them. AuthInfo is
field-identical in SDK v2, so structural typing preserves interop in
both directions.
- The client OAuth provider (client/auth/providers/base.ts) stays on
the v1 SDK types pending its v2 rework, so the peer dependency is
kept but marked optional; server-only installs work without the SDK.
- Refs ECO-98
- Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>

## 0.10.1-keycardai-mcp (2026-07-02)


- fix(mcp): always emit configured issuer in authorization_servers
- The protected resource metadata handler special-cased the
mcp-protocol-version: 2025-03-26 header and overrode
authorization_servers to the resource origin. The Go SDK
(credentials-go #21, v0.10.1) and Python SDK always emit the
configured issuer per RFC 9728, so legacy clients received
[origin] from TypeScript but [issuer] from Go/Python. Drop the
shim so all three SDKs converge on the issuer.
- Legacy clients that resolve /.well-known/oauth-authorization-server
on the resource origin are still served by the proxied AS metadata
route.
- Fixes ECO-100
- Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>

## 0.10.0-keycardai-mcp (2026-06-22)


- feat(mcp): add requestScopes to AuthProvider.grant
- grant() accepts requestScopes (a string/string[] applied to every
resource, or a record keyed by resource), threaded through exchangeTokens
and applied to the per-resource token-exchange scope on both the standard
and substitute-user paths. No scope is sent when unset.

## 0.9.0-keycardai-mcp (2026-06-15)


- feat(mcp): resolve provider credentials by zone issuer URL
- AuthProvider passes its zone URL to credential resolution so
issuer-keyed multi-zone credentials resolve for the provider zone.

## 0.8.0-keycardai-mcp (2026-06-12)


- feat(mcp)!: grant fail-fast 401, stacking merge, and impersonation
- AuthProvider.grant now rejects requests without a bearer token with 401
and an RFC 6750 WWW-Authenticate challenge, merges results into a
pre-existing req.accessContext when grants are stacked, and accepts a
userIdentifier resolver that routes resource exchanges through the
substitute-user impersonation path. exchangeTokens gains an optional
options parameter carrying the resolved identifier.
- BREAKING CHANGE: requests without a bearer token are rejected with 401
before the handler runs.

## 0.7.0-keycardai-mcp (2026-06-12)


- fix(mcp): return 502 when upstream AS metadata fetch fails
- The authorization-server metadata handler now checks the upstream
response and catches fetch errors, responding 502 with a JSON error body
instead of letting the failure surface as a framework 500.

## 0.6.0-keycardai-mcp (2026-06-12)


- fix(mcp): pass the discovered token endpoint into the WebIdentity assertion
- The provider passed tokenEndpoint=undefined to prepareTokenExchangeRequest, so
a WebIdentity assertion was built with aud=iss, which the authorization server
rejects. Resolve the token endpoint via the exchange client getTokenEndpoint()
and pass it through so the assertion aud is the token endpoint.

## 0.5.0-keycardai-mcp (2026-05-19)


- fix(mcp): compare resource URL origin instead of full URL in bearer auth middleware (#54)
- * feat(oauth): export pkce authenticate and helpers from main index
- * feat(oauth): add RFC 8707 resource indicator support to authenticate and exchangeAuthorizationCode
- * fix(mcp): compare resource URL origin instead of full URL in bearer auth middleware

## 0.4.0-keycardai-mcp (2026-04-22)


- feat(mcp): thread issuer/audience through bearer middleware and verifier
- `JWTOAuthTokenVerifier` now forwards the new `JWTVerifierOptions` to the
underlying verifier. `requireBearerAuth` accepts `issuers` / `audiences`
directly and auto-constructs the default verifier with those values;
passing neither `verifier` nor `issuers` now throws at middleware
registration time, so you can't silently ship a server that accepts any
signed JWT.
- Consumers following the documented build pattern (`mcpAuthMetadataRouter`
already takes `oauthMetadata.issuer`) need only pass the same value into
`requireBearerAuth`:
-   requireBearerAuth({
    issuers: "https://your-zone.keycard.cloud",
    requiredScopes: ["mcp:tools"],
  })
- Breaking for callers that did `requireBearerAuth({ requiredScopes: [...] })`
with no issuer and relied on the implicit permissive verifier.
- Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>

## 0.3.0-keycardai-mcp (2026-03-31)


- feat(mcp)!: move @modelcontextprotocol/sdk to peerDependencies
- Consumers of @keycardai/mcp must now install @modelcontextprotocol/sdk
themselves. This prevents version conflicts when the consumer's project
(or other packages like mcp-handler) pins a specific version, avoiding
duplicate installations and runtime crashes in bundled environments.
- Bumps @keycardai/mcp to 0.2.0.
- BREAKING CHANGE: @modelcontextprotocol/sdk is no longer automatically
installed with @keycardai/mcp. Add it to your own dependencies.
