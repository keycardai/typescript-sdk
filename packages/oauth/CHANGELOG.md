## 0.8.4-keycardai-oauth (2026-06-09)


- fix(oauth): bound the JWKS key cache (evict oldest on overflow) (#66)
- JWKSOAuthKeyring's key cache was unbounded, so a long-lived verifier resolving keys across many (issuer, kid) pairs could grow without limit. It now evicts the oldest-inserted entry once the cache exceeds keyCacheMaxEntries (default 256, configurable).
- Companion to python-sdk #145; matches the ECO-35 contract that the key cache is bounded with partial eviction (exact order implementation-defined).
- Co-authored-by: Claude Opus 4.8 (1M context) <noreply@anthropic.com>

## 0.8.3-keycardai-oauth (2026-06-09)


- fix(oauth): name the authorization-server URL "issuer" consistently (#64)
- Rename the positional issuerUrl parameter to issuer across @keycardai/oauth so the authorization-server URL has one name everywhere. fetchAuthorizationServerMetadata already used issuer; the TokenExchangeClient constructor, registerClient, exchangeAuthorizationCode, and authenticate used issuerUrl.
- The parameters are positional, so this is a source-compatible rename with no call-site changes and no deprecated alias needed.
- Part of the SDK parity effort (PHILOSOPHY.md #5). Python uses issuer after ECO-30. Tracked by ECO-33.
- Co-authored-by: Claude Opus 4.8 (1M context) <noreply@anthropic.com>

## 0.8.2-keycardai-oauth (2026-06-02)


- fix(oauth): throw typed errors from authorization server discovery (#62)
- * fix(oauth): throw typed errors from authorization server discovery
- Discovery threw plain Error for non-2xx and issuer mismatch, and let ZodError
escape on a malformed body, even though the SDK ships a typed error hierarchy.
Callers could not branch on error type.
- - non-2xx -> HTTPError
- malformed JSON / invalid or issuer-less metadata -> OAuthError("invalid_metadata")
- issuer mismatch -> OAuthError("issuer_mismatch")
- Aligns TS error semantics with the Python SDK typed taxonomy.
- Closes ECO-28.
- * fix(oauth): ignore trailing slash in discovery issuer comparison
- Matches the Python SDK, which normalizes the trailing slash before comparing.
Without this the same metadata document could be accepted by one SDK and
rejected by the other.

## 0.8.1-keycardai-oauth (2026-06-02)


- fix(oauth): type grant_types_supported and response_types_supported in discovery metadata (#58)
- These two standard RFC 8414 fields were returned via schema passthrough but
untyped, so callers got no static types for them. The Python SDK types both.
Adds them as optional string arrays.
- Closes ECO-29.

## 0.8.0-keycardai-oauth (2026-05-19)


- feat(oauth): add RFC 8707 resource indicator support to authenticate and exchangeAuthorizationCode (#52)
- * feat(oauth): export pkce authenticate and helpers from main index
- * feat(oauth): add RFC 8707 resource indicator support to authenticate and exchangeAuthorizationCode

## 0.7.0-keycardai-oauth (2026-05-19)


- feat(oauth): export pkce authenticate and helpers from main index (#50)

## 0.6.0-keycardai-oauth (2026-05-06)


- feat(oauth): add PKCE primitives and authenticate() flow (ACC-258) (#22)
- * feat(oauth): add PKCE primitives and authenticate() flow (ACC-258)
- Adds RFC 7636 PKCE support under the @keycardai/oauth/pkce subpath,
closing the TS parity gap with Python keycardai.oauth.pkce. One module,
one import path, Python-equivalent surface.
- Primitives (runtime-agnostic, Web Crypto):
- generateCodeVerifier(): 32 random bytes, base64url-encoded (43 chars)
- generateCodeChallenge(verifier, method): SHA-256 + base64url for S256;
  plain returns the verifier unchanged. RFC 7636 Appendix B test vector
  passes.
- generatePkcePair(): convenience wrapper returning both.
- exchangeAuthorizationCode(issuerUrl, code, options): discovers
  token_endpoint via AS metadata, POSTs authorization_code grant with
  code_verifier. Same inline error-handling pattern as registration.ts.
- authenticate() (Node.js only):
- Full browser-launch + loopback-callback flow. Uses dynamic imports of
  node:http and node:child_process inside the function body, so the
  module can be imported safely in any runtime; Workers only fail when
  authenticate() is actually called.
- Opens the AS authorization URL in the users default browser via
  child_process.exec (no new npm deps; platform-aware open/xdg-open/start).
- Starts a local HTTP server on localhost:port, waits for the auth-code
  redirect, exchanges the code, returns TokenResponse.
- Tests: 9 new in pkce.test.ts (86 oauth total). RFC vector, verifier
format, pair consistency, plain method, exchange happy path/error/missing
endpoint/Basic auth header, authenticate() happy path and timeout.
- * fix(oauth): add @types/node dev dep for authenticate() dynamic imports
- node:http and node:child_process are dynamically imported inside
authenticate(), but TypeScript still needs type declarations to
compile the function body. @types/node as a devDependency fixes the
build without affecting consumers or the runtime-agnostic contract
of @keycardai/oauth.
- * refactor(oauth): fix async-executor anti-pattern in waitForCode
- Pull the await import("node:http") out of the new Promise() constructor
into the outer async function body. If the dynamic import throws, the
rejection now propagates through the async function rather than escaping
an async Promise executor and becoming an unhandled rejection.
- Also increase the loopback-server startup delay in the authenticate()
test from 80ms to 250ms to reduce ECONNREFUSED flake risk on loaded CI
machines.
- * fix(oauth): replace exec with execFile in openBrowser to prevent shell injection
- exec() interpolates the URL into a shell string, making it vulnerable
to command injection if the authorization URL contains shell
metacharacters. execFile() passes the URL as a distinct argument
without invoking a shell.
- On Windows, start is a cmd.exe built-in rather than a standalone
executable, so execFile("cmd", ["/c", "start", "", url]) is used
instead of execFile("start", ...).

## 0.5.0-keycardai-oauth (2026-05-05)


- fix(oauth): address PR #20 review feedback on registerClient
- - additionalMetadata now serialized first in serializeRequest so named
  fields (clientName, grantTypes, etc.) always take precedence. Previously
  additionalMetadata was spread last and could silently override typed
  fields — kamil flagged this as a blocker.
- - response.json() on the success path wrapped in try/catch. If the AS
  returns a non-JSON 2xx body, the previous code let the parse error
  propagate with no context; now throws "not valid JSON" explicitly.
- - RegisterClientOptions gains a timeoutMs field. Resolves to
  AbortSignal.timeout(ms) when no signal is already provided, consistent
  with JWKSOAuthKeyring and fetchAuthorizationServerMetadata patterns.
- Tests: named-field precedence over additionalMetadata + AbortSignal
propagation, 81 oauth passing.
- refactor(oauth): inline readJsonBody per fresh-eyes review
- Drop the readJsonBody helper. Inline body-reading at both call sites,
matching the pattern in tokenExchange.ts.
- On the error path (non-2xx): inline try/catch returning null on parse
failure, then check for RFC 6749 error fields. Same shape as the error
branch in exchangeToken.
- On the success path: read JSON directly and throw a precise error
("not a valid JSON object") rather than falling into the "missing
client_id" branch, which was misleading when the real failure was a
parse error.
- Update tests:
- Happy path: drop wire-body assertions (method, headers, body fields).
  Those test serializeRequest internals; the contract is what the caller
  receives. Assert clientName and raw instead.
- additionalMetadata: drop wire-body assertion; instead assert that
  vendor fields are surfaced in raw, which is the documented contract
  for the escape hatch.
- Add raw assertion to the happy path, since raw is the primary
  justification for the field and had no test coverage.
- feat(oauth): add registerClient for RFC 7591 dynamic client registration
- ACC-257. Closes the matrix-row gap between Python and TypeScript on
dynamic client registration. Mirrors the Python AsyncClient.register_client
signature.
- Public surface in @keycardai/oauth/registration:
- - registerClient(issuerUrl, request, options?) async function. Discovers
  registration_endpoint from the AS metadata, POSTs the request as JSON,
  returns the issued client credentials. Throws OAuthError on RFC 6749
  error responses, plain Error on missing registration_endpoint or
  non-OAuth HTTP failures.
- ClientRegistrationRequest interface: typed RFC 7591 §2 client metadata.
  additionalMetadata bag for vendor extensions.
- ClientRegistrationResponse interface: typed RFC 7591 §3.2.1 fields,
  plus a raw escape hatch holding the full response body for AS-specific
  extensions.
- Independent of the package restructure (ACC-194/193/192). Touches only
@keycardai/oauth.
- Tests: 6 new in registration.test.ts (happy path, missing
registration_endpoint, OAuth error, non-OAuth HTTP failure, missing
client_id, additionalMetadata pass-through). Mocks fetch directly.
- 41 oauth tests, 61 mcp tests, 31 cloudflare tests passing across the
workspace.

## 0.4.1-keycardai-oauth (2026-05-05)


- fix(oauth): map server barrel in typesVersions for node moduleResolution (ACC-269)
- The typesVersions glob "*" maps "server" to "./dist/esm/server" —
TypeScript then looks for "./dist/esm/server.d.ts" (does not exist)
when the actual types live at "./dist/esm/server/index.d.ts". This
caused @keycardai/express to work around the issue by importing from
specific file paths (@keycardai/oauth/server/tokenVerifier etc.)
rather than the barrel.
- Add explicit entries so "server" and "server/*" resolve correctly
under any moduleResolution setting, including the legacy "node" mode
used in CJS builds.

## 0.4.0-keycardai-oauth (2026-05-01)


- feat(oauth): pass error context through AccessContext.access()
- ResourceAccessError now accepts an options bag with resource, errorType
('global_error' | 'resource_error' | 'missing_token'), availableResources,
and errorDetails. AccessContext.access() populates them at the three throw
sites so middleware can surface which resource failed and why.
- Also rename getResourceErrors -> getResourceError. The plural method name
with a singular return shape was misleading.
- ErrorDetail moves to errors.ts (re-exported from server/accessContext for
API stability) so the rich ResourceAccessError can reference it without an
import cycle.
- Mirrors python keycardai-oauth, whose ResourceAccessError already accepts
these args. Companion python-sdk PR follows to wire up the call sites
there too.
- Addresses review feedback on PR #19 from @jerriclynsjohn.
- feat(oauth): add JWKSOAuthKeyring.clear() and bring back TokenVerifier.clearCache()
- Closes the small parity gap with Python keycardai.oauth where
TokenVerifier.clear_cache() flushes the underlying JWKS key cache.
Operational hook for post-rotation flushes.
- JWKSOAuthKeyring.clear() drops cached keys, JWKS URI discoveries, and
inflight resolutions in one call. Targeted invalidate(issuer, kid) is
still the right tool when the rotation is scoped.
- TokenVerifier.clearCache() delegates to the keyring via duck typing
(checks for an optional clear() method). The OAuthKeyring interface
stays minimal at one method (key); custom implementers opt in by
exposing clear().
- Replaces the implementation-asserting cache test the fresh-eyes
review correctly flagged. The new test asserts the contract
(keyring.clear was invoked after clearCache; no-op when the keyring
does not expose clear).
- refactor(oauth): collapse TokenVerifier internals per fresh-eyes review
- Drop the per-zone JWTVerifier cache, the DEFAULT_ZONE_KEY constant, the
REQUIRED_AUDIENCE_MISSING symbol sentinel, the #getVerifier and
#resolveAudience helpers, and the public clearCache() method.
JWTVerifier construction is cheap (a handful of Set literals); the
keyring already caches JWKS lookups, which is the only cache that
affects request latency. Inline the audience resolution and verifier
construction directly in #verify. Net: 60 fewer lines, no public
behavior change.
- Also removes the test that asserted the cache existed by checking
keyring.key was called twice. That was an implementation-asserting
test, not a contract test.
- Drop the silent clientId = "" fallback in toAccessToken. JWTVerifier
already rejects tokens missing client_id (jwt/verifier.ts:115), so the
fallback was dead-defensive code that pretended to handle a state
upstream forbids.
- Add JSDoc to buildSubstituteUserToken explicitly framing it as the
Keycard vendor assertion (validated by URN at the AS, not signature)
rather than a JWT builder. Sits next to JWTSigner in jwt/, so the
distinction needs to be loud.
- Add JSDoc on TokenVerifierOptions.audience documenting the
fail-closed behavior when a zoneId has no entry in the per-zone dict.
- feat(oauth)!: add server primitives (AccessContext, TokenVerifier, ClientSecret, impersonate)
- ACC-194 foundation slice. Expands @keycardai/oauth with the server-tier
primitives the future @keycardai/express depends on. Closes the TS-side
foundation under impersonation, multi-zone, and route-level auth gating.
- New surface in @keycardai/oauth/server:
- - AccessContext: non-throwing per-resource token container with
  partial-error tracking (success / partial_error / error). Lifted from
  @keycardai/mcp/server/auth/provider; mcp re-exports it for backward
  compat so consumer imports stay valid.
- AccessToken: typed verified-token model returned by TokenVerifier
  (token, clientId, scopes, expiresAt?, resource?).
- TokenVerifier: composes JWTVerifier; adds JWKS discovery, multi-zone
  issuer/audience routing (enableMultiZone, verifyTokenForZone),
  required-scope validation. Returns AccessToken | null. Per-zone
  audience dict fails closed when a zoneId has no matching entry.
- ClientSecret: credential provider supporting (clientId, clientSecret),
  tuple [id, secret], or zone-keyed Record<zoneId, [id, secret]>. Lifted
  from mcp; mcp re-exports it.
- New on TokenExchangeClient:
- - impersonate({ userIdentifier, resource, scope?, zoneId? }): RFC 8693
  substitute-user exchange via the
  urn:keycard:params:oauth:token-type:substitute-user URN.
- credential constructor option accepts an ApplicationCredential. When
  set, takes precedence over static clientId/clientSecret.
- exchangeToken accepts an optional { zoneId } second arg for per-zone
  Basic auth resolution.
- TokenType const exposes ACCESS_TOKEN and SUBSTITUTE_USER URNs.
- Other:
- - buildSubstituteUserToken(identifier) helper at
  @keycardai/oauth/jwt/substituteUser.
- ApplicationCredential interface widens additively: getAuth(zoneId?)
  and optional zoneId on prepareTokenExchangeRequest options. All four
  existing implementers (cloudflare WorkersClientSecret,
  WorkersWebIdentity; mcp ClientSecret, WebIdentity, EKSWorkloadIdentity)
  satisfy the new contract without changes.
- ResourceAccessError, AuthProviderConfigurationError lifted into
  @keycardai/oauth/errors. mcp re-exports.
- New subpath exports: ./server, ./server/{accessContext,accessToken,
  tokenVerifier,clientSecret}, ./jwt/substituteUser. Bumps oauth to 0.4.0.
- Tests:
- - oauth: +33 tests across accessContext, substituteUser, clientSecret,
  tokenVerifier, tokenExchange.impersonate. 68 passing.
- mcp: 61 unchanged tests pass against the lifted classes (load-bearing
  backward-compat check).
- cloudflare: 31 tests pass.
- Out of scope for this PR (deferred):
- - WebIdentity / EKSWorkloadIdentity stay in mcp; filesystem deps,
  not load-bearing for the matrix-row flips here.
- exchangeTokensForResources orchestrator: not needed until
  @keycardai/express.
- registerClient (RFC 7591): standalone PR.
- PKCE generation: separate ticket.

## 0.3.0-keycardai-oauth (2026-04-22)


- fix(oauth): drop Python-parity reference from audience comment
- Per review feedback — the comment should explain the behavior to a
reader of this code, not reference the porting history.
- Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
- feat(oauth): bind JWTVerifier to configured issuer, add audience and alg checks
- The current JWTVerifier resolves the signing key from the token's own `iss`
claim with no allowlist, so any attacker who controls an OAuth-discoverable
host can forge a JWT that passes verification. This is the load-bearing
fix for the SDK-side auth bypass tracked in ACC-149.
- New `JWTVerifierOptions` mirrors the pattern used in @keycardai/python-sdk's
TokenVerifier:
- - `issuers` (required) — exact-match allowlist applied BEFORE any keyring
  lookup, so a forged `iss` cannot trigger OAuth discovery against an
  attacker-controlled URL
- `audiences` (optional) — when set, the token's `aud` must be present and
  contain a matching value; missing `aud` fails closed
- `algorithms` (default `["RS256"]`) — rejects `alg: "none"` and anything
  outside the allowlist before signature verification
- `clockSkewSec` (default 0) — applied to both `exp` and `nbf` checks
- Required claims (RFC 9068 § 2.2): tokens missing `iss`, `exp`, or
`client_id` are rejected.
- Verification order is now: alg → iss → required claims → time → audience
→ signature. Every cheap policy check runs before the keyring is consulted,
so an invalid token cannot force a network round-trip.
- Breaking change for any direct `new JWTVerifier(keyring)` caller — add
`{ issuers: "https://your-zone.keycard.cloud" }`.
- Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>

## 0.2.0-keycardai-oauth (2026-03-31)


- test(oauth): add JWKSOAuthKeyring caching tests
- 16 tests covering cache hits, TTL expiration, concurrency dedup,
SSRF origin validation, invalidation, error recovery, fetch timeouts,
and backward compatibility.
- feat(oauth): add two-level JWKS caching to JWKSOAuthKeyring
- Add in-memory TTL caches for discovery (issuer -> jwks_uri, 1h default)
and keys (issuer::kid -> CryptoKey, 5min default) with Promise-based
concurrency dedup and SSRF origin validation.
- Closes #4
