## 0.22.0-keycardai-oauth (2026-08-31)


- feat(oauth): send client_id on the client-credentials grant (#159)
- The jwt-bearer assertion of a federation-rule WorkloadIdentity needs the
client_id form parameter for the zone to resolve the credential by
application ID.
- Co-authored-by: devin-ai-keycard <devin-ai@keycard.ai>
Co-authored-by: Larry Osakwe <larry@keycard.ai>

## 0.21.0-keycardai-oauth (2026-08-31)


- feat(oauth): web-app authorization flow with multi-resource begin and UserInfo (#155)
- Adds beginAuthorization/completeAuthorization and fetchUserInfo to @keycardai/oauth, plus typed OIDC fields on discovered metadata.
- Co-authored-by: devin-ai-keycard <devin-ai@keycard.ai>
Co-authored-by: Larry Osakwe <larry@keycard.ai>

## 0.20.0-keycardai-oauth (2026-07-16)


- feat(oauth): add WorkloadIdentity credential with pluggable subject token sources (#118)
- * feat(oauth): add WorkloadIdentity credential with pluggable subject token sources
- One generic WorkloadIdentity credential owns the exchange contract
(jwt-bearer client assertion, no basic auth, fresh fetch per exchange,
no caching). A one-method SubjectTokenSource interface is the only
per-platform code: FileTokenSource (EKS, AKS, Kubernetes projected
tokens), GCPMetadataTokenSource (GKE, GCE, Cloud Run), FlyTokenSource
(Fly Machines), or any bare function.
- The optional clientId option is sent as the client_id form parameter
alongside the assertion; token-federation application credentials
(KEP 108) are resolved by it. TokenExchangeRequest gains a clientId
field serialized as client_id.
- EKSWorkloadIdentity becomes a deprecated subclass over FileTokenSource
with unchanged signature and EKS-only env discovery. Its failures are
now typed WorkloadIdentity{Configuration,Runtime}Error (Error
subclasses) instead of plain Error, aligning the error taxonomy with
the spec.
- Implements the workload-identity spec (keycard-sdk-spec#39). ECO-111.
- * refactor(oauth): rename IdentityTokenSource from SubjectTokenSource
- The source returns the platform-issued OIDC identity token, which the
credential attaches as the client assertion. Naming it a subject token
collided with TokenExchangeRequest.subjectToken, which carries the
inbound user token on the RFC 8693 exchange.
- * fix(oauth): surface the Fly timeout error unwrapped; assert client_id on the wire
- The Machines API timeout error was re-wrapped by the error handler
with the generic unreachable-socket message, burying the timeout on
cause. Typed errors now pass through the handler untouched.
- Adds a wire-level test that clientId serializes as the client_id form
parameter on token exchange.
- * test(mcp): assert the typed error from the re-exported EKS credential
- EKSWorkloadIdentity failures are WorkloadIdentityConfigurationError
now that the credential wraps FileTokenSource; the test asserted the
old plain-Error message casing.

## 0.19.0-keycardai-oauth (2026-06-15)


- fix(oauth): raise typed OAuthError("invalid_response") on malformed token responses
- Token exchange, client credentials, authorization-code exchange, and
dynamic client registration now raise OAuthError with the
invalid_response code on a malformed or unparseable success/error body
(missing access_token, non-OK response with no parseable OAuth error,
non-JSON body, missing client_id), instead of a plain Error. This
matches the discovery path and Python, so a caller can switch on the
same discriminator across operations and SDKs.
- feat(oauth)!: key multi-zone credentials by issuer and rename the per-call selector
- ApplicationCredential.getAuth takes the zone issuer URL; multi-zone
ClientSecret maps are keyed by issuer URL with trailing-slash
normalization, fail-closed on unknown issuers. ExchangeOptions,
ImpersonateRequest, RequestTokenOptions, and
prepareTokenExchangeRequest name the per-call selector issuer.
- BREAKING CHANGE: multi-zone ClientSecret maps are keyed by issuer URL
instead of zone id, and the per-call zoneId selector is renamed issuer.

## 0.18.0-keycardai-oauth (2026-06-12)


- feat(oauth): add challenge-driven entry to the PKCE authenticate flow
- New resolveIssuerFromChallenge parses the RFC 9728 resource_metadata
parameter from a WWW-Authenticate header, fetches the protected-resource
metadata document, and returns authorization_servers[0] plus the
document resource. authenticateFromChallenge composes it with
authenticate, defaulting the resource to the resolved document value
when the caller does not set one.

## 0.17.0-keycardai-oauth (2026-06-12)


- feat(oauth): add AccessContext.merge for accumulating grant results
- merge(other) folds another context into this one: tokens and
per-resource errors accumulate (later wins per resource), an incoming
global error overwrites, and absence preserves the existing value. The
accessor surface is unchanged.

## 0.16.0-keycardai-oauth (2026-06-12)


- feat(oauth): default token_type to Bearer, parse id_token, add buildAuthorizeUrl
- Token responses now default token_type to Bearer when the server omits
the field (the RFC 6750 scheme name) and parse an optional id_token into
TokenResponse.idToken. The authorization-code exchange reuses the shared
token-response deserializer.
- New buildAuthorizeUrl(authorizationEndpoint, params) builds an
RFC 6749 section 4.1.1 + RFC 7636 authorize URL for callers that manage
the redirect themselves; authenticate now uses it internally.

## 0.14.0-keycardai-oauth (2026-06-12)


- feat(oauth): add ClientCredentialsClient
- Adds an RFC 6749 section 4.4 client credentials grant client.
ClientCredentialsClient takes the issuer and a static client id/secret
or an ApplicationCredential (with per-call zoneId resolution), lazily
discovers the token endpoint, and parses RFC 6749 error responses into
OAuthError. The token-response deserializer is now exported from the
token-exchange module and shared. ECO-43.

## 0.13.0-keycardai-oauth (2026-06-12)


- feat(oauth)!: add CSRF state to authenticate and align PKCE defaults
- The high-level authenticate flow now generates a random state value,
sends it on the authorization URL, and rejects redirects whose state
does not match (RFC 6749 section 10.12). An openBrowser option allows
supplying a custom launcher for the authorization URL.
- Defaults aligned with the Python SDK: loopback port 8765 (was 8080),
callback timeout 300s (was 60s), and code verifier length 128 (was 43).
generateCodeVerifier and generatePkcePair accept an explicit verifier
length within the RFC 7636 43-128 range.
- BREAKING CHANGE: the default loopback port is now 8765; clients whose
registered redirect URI pins http://localhost:8080/callback must pass
port: 8080 explicitly. Redirects without a matching state are rejected.

## 0.12.0-keycardai-oauth (2026-06-12)


- feat(oauth)!: WebIdentity signs the registered clientId as iss/sub and requires the token endpoint for aud
- Keycard svc-sts validates a private_key_jwt assertion by looking up the client
by `sub` (the registered application-credential identifier) and requires `aud`
to be the token endpoint URL (RFC 7523). WebIdentity now:
- takes a `clientId` (the registered credential identifier) and signs it as the
  assertion `iss`/`sub`; an explicit `resource_client_id` in the exchange
  authInfo still overrides. The prior fallback to the local serverName/key id
  is removed (it is not the registered client id).
- requires the token endpoint for `aud`, with no fallback to `iss` (a
  self-referential `aud` is rejected by the authorization server).
- TokenExchangeClient exposes `getTokenEndpoint()` so a caller can resolve the
discovered token endpoint to build the assertion before exchanging.
- Resolves the issuer/audience-resolution row of the web-identity spec (ECO-39).

## 0.11.0-keycardai-oauth (2026-06-11)


- feat(oauth): default WebIdentity key storage to ./server_keys with ./mcp_keys fallback (#76)
- WebIdentity defaulted its key-storage directory to ./mcp_keys. Default to
./server_keys instead (a generic server-identity credential, not MCP-specific),
matching the Python default. When storageDir is omitted, fall back to ./mcp_keys
if it exists and ./server_keys does not, so an existing deployment keeps its keys
after upgrade. An explicit storageDir is unaffected.
- Part of the web-identity spec default-storage-directory row (ECO-39).

## 0.10.0-keycardai-oauth (2026-06-11)


- feat(oauth): add registration-request auth (initial access token) to registerClient (#74)
- registerClient sent no Authorization header, so it could not register against
an authorization server whose registration endpoint requires authentication.
Add an optional initialAccessToken (RFC 7591 section 3.1), sent as a Bearer
credential on the registration POST. Brings TS to parity with Python, which
authenticates the registration request via its client auth strategy.
- Part of the dynamic-client-registration spec (ECO-44).

## 0.9.1-keycardai-oauth (2026-06-11)


- fix(oauth): reject empty client_id/client_secret at ClientSecret construction (#72)
- ClientSecret validated the type of client_id/client_secret but accepted empty
strings on all three construction shapes (two-arg, tuple, multi-zone dict).
Python rejects empty credentials at construction; this brings TypeScript to
parity so a misconfigured credential fails fast rather than producing a token
request the authorization server will reject.
- Part of the client-secret spec construction-validation row (ECO-38).

## 0.9.0-keycardai-oauth (2026-06-11)


- feat(oauth)!: enforce the full RFC 9068 required-claim set in the JWT verifier (#70)
- The verifier now requires iss, sub, aud, exp, iat, and client_id on every
access token, per RFC 9068 section 2.2. Previously only iss, exp, and
client_id were required, and aud was validated only when audiences were
configured. aud is now always required to be present; the audiences option
continues to control which aud values are accepted.
- Aligns the required-claim set with the Python verifier (jwt-signing-and-verification spec, ECO-36).

## 0.8.5-keycardai-oauth (2026-06-09)


- fix(oauth): typed JWKS errors + align discovery malformed-doc code to invalid_response (#67)
- JWKSOAuthKeyring threw plain Error; it now throws a JWKSError subclass (JWKSDiscoveryError / JWKSUriValidationError / JWKSFetchError / JWKSKeyNotFoundError), exported from the package root, mirroring Python's taxonomy. Discovery now raises invalid_response (was invalid_metadata) for a malformed metadata document, matching Python; issuer_mismatch unchanged.
- Closes the TS side of the jwks-caching error-taxonomy row (ECO-35) and the authorization-server-discovery malformed-doc row (ECO-32). Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>

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

## 0.15.0-keycardai-oauth (2026-06-12)


- feat(oauth): default token_type to Bearer, parse id_token, add buildAuthorizeUrl
- Token responses now default token_type to Bearer when the server omits
the field (the RFC 6750 scheme name) and parse an optional id_token into
TokenResponse.idToken. The authorization-code exchange reuses the shared
token-response deserializer.
- New buildAuthorizeUrl(authorizationEndpoint, params) builds an
RFC 6749 section 4.1.1 + RFC 7636 authorize URL for callers that manage
the redirect themselves; authenticate now uses it internally.

## 0.14.0-keycardai-oauth (2026-06-12)


- feat(oauth): add ClientCredentialsClient
- Adds an RFC 6749 section 4.4 client credentials grant client.
ClientCredentialsClient takes the issuer and a static client id/secret
or an ApplicationCredential (with per-call zoneId resolution), lazily
discovers the token endpoint, and parses RFC 6749 error responses into
OAuthError. The token-response deserializer is now exported from the
token-exchange module and shared. ECO-43.

## 0.13.0-keycardai-oauth (2026-06-12)


- feat(oauth)!: add CSRF state to authenticate and align PKCE defaults
- The high-level authenticate flow now generates a random state value,
sends it on the authorization URL, and rejects redirects whose state
does not match (RFC 6749 section 10.12). An openBrowser option allows
supplying a custom launcher for the authorization URL.
- Defaults aligned with the Python SDK: loopback port 8765 (was 8080),
callback timeout 300s (was 60s), and code verifier length 128 (was 43).
generateCodeVerifier and generatePkcePair accept an explicit verifier
length within the RFC 7636 43-128 range.
- BREAKING CHANGE: the default loopback port is now 8765; clients whose
registered redirect URI pins http://localhost:8080/callback must pass
port: 8080 explicitly. Redirects without a matching state are rejected.

## 0.12.0-keycardai-oauth (2026-06-12)


- feat(oauth)!: WebIdentity signs the registered clientId as iss/sub and requires the token endpoint for aud
- Keycard svc-sts validates a private_key_jwt assertion by looking up the client
by `sub` (the registered application-credential identifier) and requires `aud`
to be the token endpoint URL (RFC 7523). WebIdentity now:
- takes a `clientId` (the registered credential identifier) and signs it as the
  assertion `iss`/`sub`; an explicit `resource_client_id` in the exchange
  authInfo still overrides. The prior fallback to the local serverName/key id
  is removed (it is not the registered client id).
- requires the token endpoint for `aud`, with no fallback to `iss` (a
  self-referential `aud` is rejected by the authorization server).
- TokenExchangeClient exposes `getTokenEndpoint()` so a caller can resolve the
discovered token endpoint to build the assertion before exchanging.
- Resolves the issuer/audience-resolution row of the web-identity spec (ECO-39).

## 0.11.0-keycardai-oauth (2026-06-11)


- feat(oauth): default WebIdentity key storage to ./server_keys with ./mcp_keys fallback (#76)
- WebIdentity defaulted its key-storage directory to ./mcp_keys. Default to
./server_keys instead (a generic server-identity credential, not MCP-specific),
matching the Python default. When storageDir is omitted, fall back to ./mcp_keys
if it exists and ./server_keys does not, so an existing deployment keeps its keys
after upgrade. An explicit storageDir is unaffected.
- Part of the web-identity spec default-storage-directory row (ECO-39).

## 0.10.0-keycardai-oauth (2026-06-11)


- feat(oauth): add registration-request auth (initial access token) to registerClient (#74)
- registerClient sent no Authorization header, so it could not register against
an authorization server whose registration endpoint requires authentication.
Add an optional initialAccessToken (RFC 7591 section 3.1), sent as a Bearer
credential on the registration POST. Brings TS to parity with Python, which
authenticates the registration request via its client auth strategy.
- Part of the dynamic-client-registration spec (ECO-44).

## 0.9.1-keycardai-oauth (2026-06-11)


- fix(oauth): reject empty client_id/client_secret at ClientSecret construction (#72)
- ClientSecret validated the type of client_id/client_secret but accepted empty
strings on all three construction shapes (two-arg, tuple, multi-zone dict).
Python rejects empty credentials at construction; this brings TypeScript to
parity so a misconfigured credential fails fast rather than producing a token
request the authorization server will reject.
- Part of the client-secret spec construction-validation row (ECO-38).

## 0.9.0-keycardai-oauth (2026-06-11)


- feat(oauth)!: enforce the full RFC 9068 required-claim set in the JWT verifier (#70)
- The verifier now requires iss, sub, aud, exp, iat, and client_id on every
access token, per RFC 9068 section 2.2. Previously only iss, exp, and
client_id were required, and aud was validated only when audiences were
configured. aud is now always required to be present; the audiences option
continues to control which aud values are accepted.
- Aligns the required-claim set with the Python verifier (jwt-signing-and-verification spec, ECO-36).

## 0.8.5-keycardai-oauth (2026-06-09)


- fix(oauth): typed JWKS errors + align discovery malformed-doc code to invalid_response (#67)
- JWKSOAuthKeyring threw plain Error; it now throws a JWKSError subclass (JWKSDiscoveryError / JWKSUriValidationError / JWKSFetchError / JWKSKeyNotFoundError), exported from the package root, mirroring Python's taxonomy. Discovery now raises invalid_response (was invalid_metadata) for a malformed metadata document, matching Python; issuer_mismatch unchanged.
- Closes the TS side of the jwks-caching error-taxonomy row (ECO-35) and the authorization-server-discovery malformed-doc row (ECO-32). Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>

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
