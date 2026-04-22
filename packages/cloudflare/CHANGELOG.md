## 0.3.0-keycardai-cloudflare (2026-04-22)


- feat(cloudflare): require trusted issuer for bearer auth
- `verifyBearerToken` now requires `issuers` (and accepts optional
`audiences`) and forwards them to the underlying JWTVerifier. The worker
wrapper passes `env.KEYCARD_ISSUER` through automatically, so anyone using
`createKeycardWorker` keeps working without config changes.
- The module-level verifier cache is now keyed by the issuer/audience
config so different callers within the same isolate get isolated
verifiers instead of a shared permissive one.
- Breaking for callers that invoked `verifyBearerToken(req)` directly — add
`{ issuers: env.KEYCARD_ISSUER }`.
- Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>

## 0.2.0-keycardai-cloudflare (2026-04-06)


- fix(cloudflare): address review nits
- - Remove dead `resource` variable in handleProtectedResourceMetadata
  (computed but never used — response already uses `baseUrl`)
- Fix audience check in verifyBearerToken to compare origin only,
  not full URL including path+query. A token scoped to
  https://example.com should validate for requests to any path
  on that origin.
- Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
- feat(cloudflare): add @keycardai/cloudflare package for Workers auth
- - createKeycardWorker() high-level wrapper: CORS, metadata, bearer auth, delegation
- JWT verification via @keycardai/oauth keyring (JWKS discovery + caching)
- IsolateSafeTokenCache: per-user token cache with request deduplication
- WorkersClientSecret and WorkersWebIdentity credential modes
- Extract ApplicationCredential interface to @keycardai/oauth/credentials
  so @keycardai/mcp and @keycardai/cloudflare share a single source of truth
- Full example in examples/cloudflare-worker/
- 30 tests passing, builds clean, strict TypeScript
- Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
