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
