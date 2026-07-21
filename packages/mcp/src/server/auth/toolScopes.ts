import { InsufficientScopeError } from "@keycardai/oauth/errors";
import type { AuthInfo } from "../../shared/auth.js";

/**
 * The slice of the MCP v2 tool handler context that carries HTTP transport
 * authentication. Structurally compatible with the `ctx` argument the
 * `@modelcontextprotocol/server` request handlers receive, so handlers can
 * pass their context straight through without depending on that package's
 * types here.
 */
export interface ToolAuthContext {
  http?: {
    authInfo?: AuthInfo;
  };
}

/**
 * Returns the required scopes the current tool call's access token does not
 * carry. An unauthenticated call (no `ctx.http.authInfo`) grants nothing, so
 * every required scope is reported missing.
 *
 * All MCP tools share one HTTP route, so route-level `requiredScopes` on
 * `requireBearerAuth` can only express scopes common to every tool. Per-tool
 * requirements are checked inside the tool handler with this helper.
 */
export function missingToolScopes(
  ctx: ToolAuthContext,
  requiredScopes: readonly string[],
): string[] {
  const grantedScopes = new Set(ctx.http?.authInfo?.scopes ?? []);
  return requiredScopes.filter((scope) => !grantedScopes.has(scope));
}

/**
 * Asserts that the current tool call is authenticated and its access token
 * carries every required scope, returning the validated `AuthInfo`.
 *
 * Throws `InsufficientScopeError` (OAuth error code `insufficient_scope`)
 * when the call is unauthenticated or scopes are missing. Use
 * `missingToolScopes` instead to shape a custom tool result for scope
 * step-up flows.
 *
 * ```ts
 * server.registerTool("delete_repo", config, async (args, ctx) => {
 *   const authInfo = requireToolScopes(ctx, ["repo:delete"]);
 *   // ...
 * });
 * ```
 */
export function requireToolScopes(
  ctx: ToolAuthContext,
  requiredScopes: readonly string[],
): AuthInfo {
  const authInfo = ctx.http?.authInfo;
  if (!authInfo) {
    throw new InsufficientScopeError(
      "Tool call is not authenticated; no access token information is available on the request context",
    );
  }

  const missingScopes = missingToolScopes(ctx, requiredScopes);
  if (missingScopes.length > 0) {
    throw new InsufficientScopeError(
      `Tool call requires additional scopes: ${missingScopes.join(" ")}`,
    );
  }

  return authInfo;
}
