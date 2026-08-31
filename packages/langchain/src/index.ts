/**
 * Keycard integration for LangChain agents.
 *
 * Adds delegated access at the tool-call boundary: every tool call gets a
 * short-lived credential brokered by Keycard, scoped to the identity the agent
 * is acting for, and audited as a delegation chain.
 *
 * ```ts
 * import { createAgent } from "langchain";
 * import { Access, getAccessContext, keycardGrantMiddleware } from "@keycardai/langchain";
 *
 * const CALENDAR = "https://www.googleapis.com/calendar/v3";
 *
 * const keycard = keycardGrantMiddleware({
 *   zoneUrl: "https://your-zone.keycard.cloud",
 *   resources: [CALENDAR],
 *   clientId: "your-agent",
 *   clientSecret: process.env.KEYCARD_CLIENT_SECRET,
 * });
 *
 * const listEvents = tool(
 *   async ({ daysAhead }) => {
 *     const token = getAccessContext().access(CALENDAR).accessToken;
 *     // ...
 *   },
 *   { name: "list_events", schema: z.object({ daysAhead: z.number() }) },
 * );
 *
 * const agent = createAgent({ model, tools: [listEvents], middleware: [keycard] });
 *
 * await agent.invoke(
 *   { messages: [{ role: "user", content: "what's on my calendar?" }] },
 *   { context: Access.onBehalfOf(callerToken) },
 * );
 * ```
 *
 * Re-export guide:
 * - Local definitions: `Access`, `keycardGrantMiddleware`, `KeycardIdentity`,
 *   `keycardIdentitySchema` (the middleware's context schema), and
 *   `getAccessContext`.
 * - Borrowed from `@keycardai/oauth`: `AccessContext` (the per-call token
 *   container) and `ResourceAccessError` (thrown only by
 *   `AccessContext.access`), re-exported so callers need one import.
 */

export { Access } from "./access.js";
export { getAccessContext } from "./accessStore.js";
export { keycardGrantMiddleware } from "./middleware.js";
export type {
  AuthorizationRequiredInterrupt,
  FallbackIdentity,
  GrantOptions,
  KeycardGrantMiddleware,
  KeycardGrantMiddlewareOptions,
  KeycardInterrupt,
  RequestScopes,
  SignInRequiredInterrupt,
} from "./middleware.js";
export { keycardIdentitySchema } from "./identity.js";
export type { KeycardIdentity } from "./identity.js";
export { KeycardZoneClient } from "./zoneClient.js";
export type { ZoneClient } from "./zoneClient.js";

export { AccessContext, ResourceAccessError } from "@keycardai/oauth";
export type { ErrorDetail, TokenResponse } from "@keycardai/oauth";
