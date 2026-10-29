import type { AuthContext } from "@grok/agent-sdk";

import { decodeClaims } from "./expiry.js";

/**
 * The attribute name carrying the inbound bearer when retention is
 * `"attributes"`.
 *
 * `AuthContext.attributes` is persisted in `SessionRecord.auth`
 * (`sessions/<id>/session.json`), so this mode puts a user bearer at rest for
 * the session's lifetime. That is why it is opt-in rather than the default.
 */
export const SUBJECT_TOKEN_ATTRIBUTE = "keycard_subject_token";

/**
 * Where the verified inbound bearer lives between `bearerAuth` admitting the
 * request and the exchange in `onBehalfOf`.
 *
 * Two implementations ship: {@link memorySubjectTokenStore} (the default,
 * process-local, nothing at rest) and the `"attributes"` retention mode, which
 * rides on the session record instead. Neither reaches the model: the token
 * is never a tool argument, a connection schema field, or a message.
 */
export interface SubjectTokenStore {
  get(key: string): string | undefined;
  set(key: string, token: string): void;
  delete(key: string): void;
}

/**
 * A process-local store that drops entries once their JWT `exp` has passed.
 *
 * Nothing here survives a restart, so a turn that runs in a fresh process
 * finds no subject token and fails closed with `subject_token_unavailable`
 * rather than reaching for the agent's authority.
 */
export function memorySubjectTokenStore(): SubjectTokenStore {
  const tokens = new Map<string, string>();
  return {
    get(key) {
      return tokens.get(key);
    },
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
 * The store key for one principal: the zone that issued it and its subject.
 *
 * `keycardAuth` projects `iss` onto `attributes`, so the verifier and the
 * connection factories compute the same key from the `AuthContext` alone.
 */
export function principalKey(auth: Pick<AuthContext, "principalId" | "attributes">): string {
  return `${auth.attributes?.iss ?? ""}|${auth.principalId}`;
}

/** The retained subject token for a session principal, if any. */
export function readSubjectToken(
  auth: AuthContext,
  store: SubjectTokenStore,
): string | undefined {
  const attribute = auth.attributes?.[SUBJECT_TOKEN_ATTRIBUTE];
  if (typeof attribute === "string" && attribute) return attribute;
  return store.get(principalKey(auth));
}

function tokenExpired(token: string): boolean {
  const claims = decodeClaims(token);
  if (claims === null) return false;
  const exp = claims.exp;
  return typeof exp === "number" && Number.isFinite(exp) && exp <= Date.now() / 1000;
}
