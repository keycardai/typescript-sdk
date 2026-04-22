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
