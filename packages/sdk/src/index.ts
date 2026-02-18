// @keycardai/sdk — Aggregate package re-exporting from @keycardai/oauth and @keycardai/mcp
// Users can install @keycardai/sdk for everything,
// or individual packages for smaller bundles.

// OAuth primitives
export type { OAuthKeyring, PrivateKeyring, IdentifiableKey } from "@keycardai/oauth/keyring";
export { JWKSOAuthKeyring } from "@keycardai/oauth/keyring";
export { default as base64url } from "@keycardai/oauth/base64url";
export { fetchAuthorizationServerMetadata } from "@keycardai/oauth/discovery";
export type { OAuthAuthorizationServerMetadata } from "@keycardai/oauth/discovery";
export { HTTPError, BadRequestError, UnauthorizedError, OAuthError, InvalidTokenError, InsufficientScopeError } from "@keycardai/oauth/errors";
export { JWTSigner } from "@keycardai/oauth/jwt/signer";
export type { JWTClaims } from "@keycardai/oauth/jwt/signer";
export { JWTVerifier } from "@keycardai/oauth/jwt/verifier";

// MCP OAuth integration
export { BaseOAuthClientProvider } from "@keycardai/mcp/client/auth/providers/base";
export type { OAuthTokensStore, OAuthCodeVerifierStore } from "@keycardai/mcp/client/auth/providers/base";
export { JSONWebTokenSigner } from "@keycardai/mcp/client/auth/signers/jwt";
export type { FullAuthInfo } from "@keycardai/mcp/client/auth/signers/jwt";
export { mcpAuthMetadataRouter, getOAuthProtectedResourceMetadataUrl } from "@keycardai/mcp/server/auth/router";
export type { AuthMetadataOptions, InferredAuthMetadataOptions } from "@keycardai/mcp/server/auth/router";
export { requireBearerAuth } from "@keycardai/mcp/server/auth/middleware/bearerAuth";
export type { BearerAuthMiddlewareOptions } from "@keycardai/mcp/server/auth/middleware/bearerAuth";
export { JWTOAuthTokenVerifier } from "@keycardai/mcp/server/auth/verifiers/jwt";
