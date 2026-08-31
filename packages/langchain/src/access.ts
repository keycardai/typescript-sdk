import { AuthProviderConfigurationError } from "@keycardai/oauth";
import type { KeycardIdentity } from "./identity.js";

/**
 * The three access patterns, as explicit factories.
 *
 * Each returns the context value the middleware consumes, so the pattern is
 * chosen at the call site of the run rather than inferred from which fields
 * happen to be populated:
 *
 * ```ts
 * await agent.invoke({ messages }, { context: Access.onBehalfOf(callerToken) });
 * ```
 *
 * A frozen namespace of factories, not a type: there is nothing to construct.
 */
export const Access = Object.freeze({
  /** The agent acts as itself, under its own application authority. */
  asSelf(): KeycardIdentity {
    return { asSelf: true };
  },

  /** The agent acts for the caller, exchanging the caller's Keycard token. */
  onBehalfOf(subjectToken: string): KeycardIdentity {
    if (!subjectToken || !subjectToken.trim()) {
      throw new AuthProviderConfigurationError(
        "Access.onBehalfOf requires a non-empty subject token",
      );
    }
    return { subjectToken };
  },

  /**
   * The agent acts as a specific user without holding their token. Forbidden
   * by default; requires an explicit impersonation policy in the zone.
   */
  impersonate(userIdentifier: string): KeycardIdentity {
    if (!userIdentifier || !userIdentifier.trim()) {
      throw new AuthProviderConfigurationError(
        "Access.impersonate requires a non-empty user identifier",
      );
    }
    return { userIdentifier };
  },
});
