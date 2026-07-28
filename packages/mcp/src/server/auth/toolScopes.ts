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
 * Throws `InsufficientScopeError` when the call is unauthenticated or scopes
 * are missing, which stops the handler and fails the tool call.
 *
 * What the client actually receives is a plain tool error, not an OAuth
 * challenge. `@modelcontextprotocol/server` catches every handler throw except
 * `UrlElicitationRequiredError` and flattens it into
 * `{ content: [{ type: "text", ... }], isError: true }` at HTTP 200. So the
 * `insufficient_scope` code, the 403, and the `WWW-Authenticate` header do not
 * reach the wire from here — only the error's message text does. This helper
 * enforces the requirement; it cannot signal it in a machine-readable way.
 *
 * That makes it unsuitable on its own for driving a scope step-up: the client
 * cannot distinguish missing scopes from any other tool failure. For an
 * interactive step-up, v2's own primitive is `UrlElicitationRequiredError`,
 * the one error type it re-throws rather than flattening. For a structured
 * in-band signal, use `missingToolScopes` and return a tool result your client
 * knows how to interpret.
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
