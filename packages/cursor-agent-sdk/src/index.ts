/**
 * Keycard auth for Cursor Agent SDK agents.
 *
 * Two adapters, each plugging into an SDK primitive rather than wrapping it:
 *
 * - {@link keycardAuth} is a verifier for `bearerAuth()` in a channel's auth
 *   policy chain. It verifies a zone-issued bearer and returns the SDK's
 *   `AuthContext`, retaining the token for a later on-behalf-of exchange.
 * - {@link Keycard.asSelf}, {@link Keycard.onBehalfOf} and
 *   {@link Keycard.impersonate} are connection `auth` providers: the SDK calls
 *   them at turn-build time with the session and attaches the headers they
 *   return, so no credential reaches the model.
 *
 * `@grok/agent-sdk` is imported for types only; nothing here loads SDK code.
 */
import { asSelf, impersonate, onBehalfOf } from "./connections.js";

export { keycardAuth, KEYCARD_AUTHENTICATOR } from "./keycardAuth.js";
export type { KeycardAuthOptions, KeycardTokenVerifier, SubjectTokenRetention } from "./keycardAuth.js";

export { asSelf, headersFor, impersonate, onBehalfOf } from "./connections.js";
export type { KeycardConnectionAuth, KeycardImpersonateOptions, SessionLike } from "./connections.js";

export type { KeycardConnectionOptions } from "./config.js";
export { DEFAULT_EXPIRY_SKEW_SECONDS } from "./config.js";

export { ConnectionAuthError, FailureReason } from "./errors.js";
export type { FailureReasonCode } from "./errors.js";

export { decodeClaims, subjectTokenExpired } from "./expiry.js";

export {
  defaultSubjectTokenStore,
  memorySubjectTokenStore,
  SUBJECT_TOKEN_ATTRIBUTE,
} from "./subjectTokens.js";
export type { SubjectTokenStore } from "./subjectTokens.js";

export { KeycardZoneClient } from "./zoneClient.js";
export type { ZoneClient } from "./zoneClient.js";

/** The connection auth factories, one per access pattern. */
export const Keycard = Object.freeze({ asSelf, onBehalfOf, impersonate });
