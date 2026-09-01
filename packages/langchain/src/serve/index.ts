/**
 * Inbound authentication for an agent served by LangGraph JS.
 *
 * ```ts
 * import { Auth } from "@langchain/langgraph-sdk/auth";
 * import {
 *   installOwnerAuthorization,
 *   zoneAuthenticator,
 * } from "@keycardai/langchain/serve";
 *
 * export const auth = installOwnerAuthorization(
 *   new Auth().authenticate(
 *     zoneAuthenticator({
 *       zoneUrl: process.env.KEYCARD_ZONE_URL!,
 *       resource: process.env.AGENT_RESOURCE_URL!,
 *     }),
 *   ),
 * );
 * ```
 *
 * Needs `@langchain/langgraph-sdk`, an optional peer dependency of this
 * package, which a served agent already has.
 */

export { installOwnerAuthorization, zoneAuthenticator } from "../servedAuth.js";
export type {
  VerifiedCaller,
  VerifyToken,
  ZoneAuthenticatorOptions,
  ZoneAuthUser,
} from "../servedAuth.js";
export { AUTH_USER_KEY, OWNER_KEY, SUBJECT_TOKEN_FIELD } from "../servedCaller.js";
export type { ServedCaller } from "../servedCaller.js";
