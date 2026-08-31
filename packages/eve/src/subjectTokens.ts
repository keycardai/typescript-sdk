import type { ConnectionPrincipal } from "eve/connections";
import type { SessionAuthContext } from "eve/context";

import { decodeClaims } from "./expiry.js";

/**
 * The attribute name carrying the inbound bearer when retention is
 * `"attributes"`.
 *
 * eve copies `SessionAuthContext.attributes` onto the connection principal, so
 * an attribute is the only channel eve itself offers between the auth walk and
 * a connection's `getToken`. It is also durable session state, which is why
 * this is opt-in rather than the default.
 */
export const SUBJECT_TOKEN_ATTRIBUTE = "keycard_subject_token";

/**
 * Where the verified inbound bearer lives between the auth walk and the
 * exchange in `onBehalfOf`.
 *
 * Two implementations ship: {@link memorySubjectTokenStore} (the default,
 * process-local, nothing at rest) and the `"attributes"` retention mode, which
 * puts the token on the eve session instead. Both keep the token out of model
 * input: neither is a tool argument, a connection schema field, or a message.
 */
export interface SubjectTokenStore {
  get(key: string): string | undefined;
  set(key: string, token: string): void;
  delete(key: string): void;
}

/**
 * A process-local store that drops entries once their JWT `exp` has passed.
 *
 * Nothing here survives a restart, so a turn that resumes in a fresh process
 * finds no subject token and fails closed with
 * `subject_token_unavailable` rather than reaching for the agent's authority.
 */
export function memorySubjectTokenStore(): SubjectTokenStore {
  const tokens = new Map<string, string>();
  return {
    get(key) {
      return tokens.get(key);
    },
    /**
     * Expiry is not hidden from readers: `onBehalfOf` distinguishes an expired
     * subject token from a missing one, and only the first routes to sign-in.
     * Pruning here keeps the map from growing without bound.
     */
    set(key, token) {
      for (const [existing, value] of tokens) {
        if (tokenExpired(value)) tokens.delete(existing);
      }
      tokens.set(key, token);
    },
    delete(key) {
      tokens.delete(key);
    },
  };
}

/** The default store, shared by `keycardAuth` and the connection factories. */
export const defaultSubjectTokenStore: SubjectTokenStore = memorySubjectTokenStore();

/**
 * The store key for one principal.
 *
 * Derived from the fields eve projects from the session's current auth onto
 * the connection principal, so the auth walk and `getToken` compute the same
 * key without sharing any other state.
 */
export function principalKey(
  identity:
    | Pick<SessionAuthContext, "authenticator" | "issuer" | "principalId">
    | { readonly id: string; readonly issuer?: string },
): string {
  if ("id" in identity) {
    return `${identity.issuer ?? ""}|${identity.id}`;
  }
  return `${identity.issuer ?? identity.authenticator}|${identity.principalId}`;
}

/** The retained subject token for a connection principal, if any. */
export function readSubjectToken(
  principal: ConnectionPrincipal,
  store: SubjectTokenStore,
): string | undefined {
  if (principal.type !== "user") return undefined;
  const attribute = principal.attributes?.[SUBJECT_TOKEN_ATTRIBUTE];
  if (typeof attribute === "string" && attribute) return attribute;
  return store.get(principalKey(principal));
}

function tokenExpired(token: string): boolean {
  const claims = decodeClaims(token);
  if (claims === null) return false;
  const exp = claims.exp;
  return typeof exp === "number" && Number.isFinite(exp) && exp <= Date.now() / 1000;
}
