import { AsyncLocalStorage } from "node:async_hooks";
import { AccessContext, AuthProviderConfigurationError } from "@keycardai/oauth";

/**
 * The access context in effect for the currently executing tool call.
 *
 * `AsyncLocalStorage` is the TypeScript counterpart of Python's `ContextVar`:
 * the value follows the async continuation of the tool handler and is removed
 * when the handler returns, so concurrent tool calls in the same process never
 * see each other's credentials.
 */
const store = new AsyncLocalStorage<AccessContext>();

/**
 * Run `fn` with `access` installed as the current access context.
 *
 * Generic over the return value so the same helper serves a sync tool body and
 * an async one; there is no separate async spelling.
 */
export function runWithAccessContext<T>(access: AccessContext, fn: () => T): T {
  return store.run(access, fn);
}

/**
 * The `AccessContext` for the tool call currently executing.
 *
 * Call from inside a tool. Throws when no Keycard grant middleware and no
 * `grant()` block wrapped this call.
 */
export function getAccessContext(): AccessContext {
  const access = store.getStore();
  if (access === undefined) {
    throw new AuthProviderConfigurationError(
      "No Keycard AccessContext for this tool call. Add keycardGrantMiddleware() " +
        "to the agent's middleware list and invoke the agent with an Access.* " +
        "identity as context.",
    );
  }
  return access;
}
