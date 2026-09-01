/**
 * The read side of the server's per-request identity channel.
 *
 * A LangGraph server that authenticates every request (see
 * `@keycardai/langchain/serve`) puts the verified user on the run. This module
 * reads it, and is the only place that knows the key names, so the
 * authenticate hook and the middleware agree on them.
 */

/** Where the LangGraph JS server puts the authenticated user on a run. */
export const AUTH_USER_KEY = "langgraph_auth_user";

/** The extra field on the user object carrying the caller's raw bearer. */
export const SUBJECT_TOKEN_FIELD = "subject_token";

/** The metadata field recording which identity owns a thread, run or item. */
export const OWNER_KEY = "owner";

/** A verified caller of a served run: who they are, and the bearer they sent. */
export interface ServedCaller {
  identity: string;
  subjectToken: string;
}

function field(user: unknown, name: string): unknown {
  if (user === null || typeof user !== "object") return undefined;
  return (user as Record<string, unknown>)[name];
}

function stringField(user: unknown, name: string): string | null {
  const value = field(user, name);
  return typeof value === "string" && value ? value : null;
}

/**
 * The caller whose bearer authenticated this run, or `null` if there is none.
 *
 * The server delivers the verified user to a run as
 * `configurable.langgraph_auth_user`, which middleware reads off
 * `request.runtime.configurable`. That channel is request scoped and written
 * only by the server, so two callers on one deployment never see each other's
 * identity, and a caller cannot name an identity in the request body.
 */
export function callerFromRuntime(runtime: unknown): ServedCaller | null {
  if (runtime === null || typeof runtime !== "object") return null;
  const configurable = (runtime as { configurable?: unknown }).configurable;
  if (configurable === null || typeof configurable !== "object") return null;
  const user = (configurable as Record<string, unknown>)[AUTH_USER_KEY];
  const identity = stringField(user, "identity");
  const subjectToken = stringField(user, SUBJECT_TOKEN_FIELD);
  if (identity === null || subjectToken === null) return null;
  return { identity, subjectToken };
}
