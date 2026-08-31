/**
 * Keycard auth for eve agents.
 *
 * Three adapters, each plugging into an eve primitive rather than wrapping it:
 *
 * - {@link keycardAuth} is an `AuthFn` for a channel's ordered `auth` array.
 *   It verifies a zone-issued bearer and projects the claims onto eve's
 *   `SessionAuthContext`.
 * - {@link Keycard.asSelf}, {@link Keycard.onBehalfOf}, and
 *   {@link Keycard.impersonate} are connection auth definitions: eve resolves
 *   the principal from the turn, calls `getToken` at the tool boundary, and
 *   attaches the bearer itself, so no credential reaches the model.
 * - {@link Keycard.interactive} is the interactive form. eve emits
 *   `authorization.required`, parks the turn durably on its own callback, and
 *   settles it once.
 */
export { keycardAuth } from "./auth.js";
export type { KeycardAuthOptions, SubjectTokenRetention } from "./auth.js";

export { asSelf, impersonate, onBehalfOf } from "./connections.js";
export type { KeycardImpersonateOptions } from "./connections.js";

export { interactive, memoryAuthorizedTokenStore } from "./interactive.js";
export type {
  AuthorizedToken,
  AuthorizedTokenStore,
  KeycardInteractiveOptions,
  KeycardResumeState,
  WebAppFlow,
} from "./interactive.js";

export type { KeycardConnectionOptions } from "./config.js";

export {
  AuthorizationFailedError,
  AuthorizationRequiredError,
  FailureReason,
  RouteRejectedError,
} from "./errors.js";

export { decodeClaims, subjectTokenExpired } from "./expiry.js";

export { requireAuthOnUnauthorized } from "./requireAuth.js";
export type { RequireAuthContext } from "./requireAuth.js";

export {
  defaultSubjectTokenStore,
  memorySubjectTokenStore,
  SUBJECT_TOKEN_ATTRIBUTE,
} from "./subjectTokens.js";
export type { SubjectTokenStore } from "./subjectTokens.js";

export { KeycardZoneClient } from "./zoneClient.js";
export type { ZoneClient } from "./zoneClient.js";

import { asSelf, impersonate, onBehalfOf } from "./connections.js";
import { interactive } from "./interactive.js";

/**
 * The connection auth factories, grouped for the common
 * `auth: Keycard.onBehalfOf({ ... })` call site.
 */
export const Keycard = Object.freeze({
  asSelf,
  impersonate,
  interactive,
  onBehalfOf,
});
