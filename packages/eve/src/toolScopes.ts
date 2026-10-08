import { InsufficientScopeError } from "@keycardai/oauth";
import type { SessionAuthContext } from "eve/context";

import { parseScopes } from "./auth.js";

/**
 * The slice of eve's tool context the scope helpers read. Structural, so a
 * test can pass a plain object and any eve `SessionContext` satisfies it.
 */
export interface ToolScopeContext {
  readonly session: {
    readonly auth: {
      readonly current: SessionAuthContext | null;
    };
  };
}

export interface ToolScopeOptions {
  /**
   * Keycard zone URL (issuer). When set, only a principal whose `issuer` is
   * this zone counts, the rule `keycardAuth` applies to a bearer. Without it,
   * any principal `keycardAuth` authenticated counts.
   */
  zoneUrl?: string;
}

/**
 * The turn's Keycard principal, or `null` when the caller was authenticated
 * by another entry in the channel's auth walk or not at all.
 */
function keycardPrincipal(
  ctx: ToolScopeContext,
  options: ToolScopeOptions,
): SessionAuthContext | null {
  const current = ctx.session.auth.current;
  if (current === null || current.authenticator !== "keycard") return null;
  if (current.issuer === undefined) return null;
  if (options.zoneUrl !== undefined && current.issuer !== options.zoneUrl.replace(/\/+$/, "")) {
    return null;
  }
  return current;
}

/**
 * The required scopes the inbound Keycard token does not carry.
 *
 * Scopes are read from the `scope` attribute `keycardAuth` projects onto the
 * turn's `ctx.session.auth.current`, in either the space-delimited or the list
 * form. A `scope` attribute set by a non-Keycard principal is ignored, and a
 * turn with no Keycard principal is missing every scope.
 */
export function missingToolScopes(
  ctx: ToolScopeContext,
  requiredScopes: readonly string[],
  options: ToolScopeOptions = {},
): string[] {
  const principal = keycardPrincipal(ctx, options);
  if (principal === null) return [...requiredScopes];
  const granted = new Set(parseScopes(principal.attributes.scope));
  return requiredScopes.filter((scope) => !granted.has(scope));
}

/**
 * Require every scope in `requiredScopes` on the inbound Keycard token.
 *
 * Returns the Keycard principal when it holds every scope. Throws
 * `InsufficientScopeError` when the turn has no Keycard principal or any
 * scope is missing. eve catches a throw from a tool body and hands the model
 * the error message as a failed tool call; no OAuth challenge reaches the
 * caller. For scopes every tool needs, use `keycardAuth({ requiredScopes })`.
 */
export function requireToolScopes(
  ctx: ToolScopeContext,
  requiredScopes: readonly string[],
  options: ToolScopeOptions = {},
): SessionAuthContext {
  const principal = keycardPrincipal(ctx, options);
  if (principal === null) {
    throw new InsufficientScopeError(
      "Tool call is not authenticated by Keycard; no inbound token is available on the session",
    );
  }
  const missing = missingToolScopes(ctx, requiredScopes, options);
  if (missing.length > 0) {
    throw new InsufficientScopeError(
      `Tool call requires additional scopes: ${missing.join(" ")}`,
    );
  }
  return principal;
}
