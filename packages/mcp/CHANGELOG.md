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
