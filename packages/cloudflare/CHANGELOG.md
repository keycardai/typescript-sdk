## 0.4.0-keycardai-cloudflare (2026-07-30)


- fix(cloudflare): JWKS error mapping, audiences passthrough, README compile fixes, PKCS#1 rejection (#128)
- * docs(cloudflare): fix README token exchange example to compile against the real API
- The example constructed IsolateSafeTokenCache({ zoneUrl, credential })
and called getToken(auth, resource), neither of which exists. The cache
takes a TokenExchangeClient plus an options bag, and getToken takes
(subject, subjectToken, resource) and returns a TokenResponse whose
accessToken is the upstream bearer token. Rewrite the snippet to match
the actual API, mirroring examples/cloudflare-worker.
- Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
- * fix(cloudflare): return 401/503 (not blanket 401) for JWKS errors in verifyBearerToken
- verifyBearerToken caught every unexpected error and returned a generic
401, so a JWKS or discovery outage was misreported to clients as an
auth failure and the WWW-Authenticate challenge sent them into a
pointless re-authorization loop.
- Port the semantics of the mcp package's requireBearerAuth fix (#123):
- - JWKSKeyNotFoundError (forged token, or signing key rotated out of
  the JWKS) -> 401 invalid_token + WWW-Authenticate challenge so the
  client re-runs authorization.
- JWKSError / HTTPError / OAuthError (JWKS fetch, discovery, malformed
  metadata) -> 503 temporarily_unavailable with a small JSON body and
  no WWW-Authenticate, since this is a retryable server-side failure,
  not an auth failure.
- Genuinely unexpected errors are rethrown so they surface through the
  Worker's own error handling instead of masquerading as a 401. This is
  the Workers analog of the Express middleware's next(error).
- Re-export the JWKS error taxonomy from the package so callers can catch
the classes themselves, mirroring @keycardai/mcp.
- Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
- * feat(cloudflare): expose audiences on createKeycardWorker options
- BearerAuthOptions.audiences existed but createKeycardWorker had no way
to set it, so wrapper users could not pin token audience validation and
any token from the trusted issuer was accepted regardless of which
resource it was minted for.
- Add audiences to KeycardWorkerOptions and pass it through to
verifyBearerToken. Document it in the README and the cloudflare-worker
example, binding it to the Worker's public URL (the resource identifier
registered in Keycard), matching how the go-sdk examples bind audiences.
- Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
- * fix(cloudflare): always emit configured issuer in authorization_servers
- Remove the MCP protocol version 2025-03-26 shim that rewrote
authorization_servers to the resource's own base URL. PR #108 (ECO-100)
dropped this from @keycardai/mcp; the cloudflare copy of the shim
survived only here. The Worker does not implement authorization server
endpoints itself, so pointing 2025-03-26 clients at the base URL sends
them to endpoints that do not exist.
- The /.well-known/oauth-authorization-server proxy's resource= rewrite
of authorization_endpoint is a different, specified shim and stays.
- Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
- * fix(cloudflare): reject PKCS#1 private keys with a clear conversion error
- WorkersWebIdentity stripped BEGIN RSA PRIVATE KEY headers but always
imported the DER as pkcs8, so a genuine PKCS#1 key (the OpenSSL 1.x
'openssl genrsa' default) failed deep inside crypto.subtle.importKey
with an opaque DataError. WebCrypto has no PKCS#1 import path and
converting the DER by hand is not worth a parser, so detect the PKCS#1
header up front and throw an error that tells the user to convert with
'openssl pkcs8 -topk8 -nocrypt'.
- Update the cloudflare-worker example README to generate the key with
'openssl genpkey', which emits PKCS#8 on every OpenSSL version, and
document the conversion for existing PKCS#1 keys.
- Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
- * fix(cloudflare): refuse empty token-cache subjects, guard the doc pattern
- IsolateSafeTokenCache.getToken now throws on an empty subject: the
cache keys upstream tokens per user, and an empty subject folds every
caller into one entry, serving one user's upstream token to another.
The README and example replace the auth.subject! assertion with an
explicit 401 guard so copy-paste code cannot reach that state. Also
detects encrypted PKCS#8 keys with a clear decryption message and notes
the passphrase prompt in the PKCS#1 message.
- Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
- ---------
- Co-authored-by: Claude Fable 5 <noreply@anthropic.com>

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
