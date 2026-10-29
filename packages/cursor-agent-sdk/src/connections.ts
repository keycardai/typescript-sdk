import type {
  AuthContext,
  ConnectionAuthProvider,
  ConnectionAuthResult,
  SessionInfo,
} from "@grok/agent-sdk";
import {
  AuthProviderConfigurationError,
  TokenType,
  type ClientCredentialsRequest,
  type TokenExchangeRequest,
  type TokenResponse,
} from "@keycardai/oauth";

import { resolveConnectionConfig, type KeycardConnectionOptions, type ResolvedConnectionConfig } from "./config.js";
import { ConnectionAuthError, FailureReason } from "./errors.js";
import { subjectTokenExpiresAt, subjectTokenExpired } from "./expiry.js";
import { KEYCARD_AUTHENTICATOR } from "./keycardAuth.js";
import { principalKey, readSubjectToken } from "./subjectTokens.js";

/** What a Keycard connection auth factory returns: the SDK's own provider type. */
export type KeycardConnectionAuth = ConnectionAuthProvider;

/** The part of a session a provider reads. `headersFor` accepts this shape too. */
export type SessionLike = Pick<SessionInfo, "auth">;

/** Options for {@link impersonate}. */
export interface KeycardImpersonateOptions extends KeycardConnectionOptions {
  /**
   * The zone user the agent acts for, resolved on every call. Omitted, the
   * Keycard principal's `principalId` is used, and a session with no Keycard
   * user principal fails with `principal_required`. A function receives the
   * session's `AuthContext` (any authenticator, or null) and returns the
   * identifier; that is how a deployment maps a chat identity to a zone user.
   */
  userIdentifier?: (auth: AuthContext | null) => string;
}

interface CachedToken {
  readonly token: string;
  /** Epoch milliseconds, or undefined when the zone sent no `expires_in`. */
  readonly expiresAt?: number;
}

/**
 * Connection auth that runs client credentials under the agent's own identity.
 *
 * Ignores `session.auth`: one cached token per connection across every
 * session, so this works on schedules and webhook-created sessions. No
 * exchange and no impersonation, so nothing about the caller reaches the zone.
 */
export function asSelf(options: KeycardConnectionOptions): KeycardConnectionAuth {
  const config = resolveConnectionConfig(options, "asSelf");
  const cache = new Map<string, CachedToken>();

  return async (): Promise<ConnectionAuthResult> =>
    withCache(config, cache, "app", () =>
      acquire(config, async () => {
        const request: ClientCredentialsRequest = {
          resource: config.resource,
          ...(config.scope ? { scope: config.scope } : {}),
          ...(await config.clientAuthFields()),
        };
        return config.zoneClient().clientCredentialsGrant(request);
      }),
    );
}

/**
 * Connection auth that exchanges the caller's own token for a resource token.
 *
 * Requires a Keycard user principal on `session.auth`, reads the subject
 * token `keycardAuth` retained for it, and fails closed with its own reason
 * at each step: `principal_required`, `subject_token_unavailable`,
 * `subject_token_expired`. Nothing here falls back to the agent's authority.
 */
export function onBehalfOf(options: KeycardConnectionOptions): KeycardConnectionAuth {
  const config = resolveConnectionConfig(options, "onBehalfOf");
  const cache = new Map<string, CachedToken>();

  return async (session: SessionLike): Promise<ConnectionAuthResult> => {
    const auth = requireKeycardUser(session.auth, config);
    const key = principalKey(auth);
    // The caller's own token bounds every turn, so it is checked before the
    // cache: a cached exchange never outlives the token it was exchanged from.
    const subjectToken = readSubjectToken(auth, config.subjectTokens);
    if (!subjectToken) {
      cache.delete(key);
      throw new ConnectionAuthError(
        FailureReason.SUBJECT_TOKEN_UNAVAILABLE,
        config.connectionName,
        "no Keycard subject token is retained for this session's principal in this " +
          "process; add keycardAuth() to the channel's auth chain, or use " +
          'retainSubjectToken: "attributes" when turns run outside the process that ' +
          "authenticated the caller",
      );
    }
    if (subjectTokenExpired(subjectToken)) {
      config.subjectTokens.delete(key);
      cache.delete(key);
      throw new ConnectionAuthError(
        FailureReason.SUBJECT_TOKEN_EXPIRED,
        config.connectionName,
        "the caller's Keycard token has expired; call the agent again with a fresh token",
      );
    }

    return withCache(
      config,
      cache,
      key,
      () =>
        acquire(config, async () => {
          const credential = config.credential();
          let request: TokenExchangeRequest;
          if (credential) {
            request = await credential.prepareTokenExchangeRequest(subjectToken, config.resource);
          } else {
            request = {
              subjectToken,
              resource: config.resource,
              subjectTokenType: TokenType.ACCESS_TOKEN,
            };
          }
          if (config.scope) request = { ...request, scope: config.scope };
          return config.zoneClient().exchangeToken(request);
        }),
      subjectTokenExpiresAt(subjectToken),
    );
  };
}

/**
 * Connection auth that acts for a zone user the agent holds no token for.
 *
 * Uses the zone's substitute-user exchange, authenticated by the application
 * credential: no subject token is involved, so this is the pattern for jobs
 * with no caller present (a schedule acting for a mapped user), not the way
 * to act for the caller. Zone policy decides which Applications may
 * impersonate whom.
 */
export function impersonate(options: KeycardImpersonateOptions): KeycardConnectionAuth {
  const config = resolveConnectionConfig(options, "impersonate");
  if (options.userIdentifier !== undefined && typeof options.userIdentifier !== "function") {
    throw new AuthProviderConfigurationError(
      "impersonate userIdentifier must be a function; rule 1 requires a fallback identity to resolve per call",
    );
  }
  const resolve = options.userIdentifier;
  const cache = new Map<string, CachedToken>();

  return async (session: SessionLike): Promise<ConnectionAuthResult> => {
    let userIdentifier: string;
    if (resolve) {
      userIdentifier = resolve(session.auth);
    } else {
      userIdentifier = requireKeycardUser(session.auth, config).principalId;
    }
    if (!userIdentifier || !userIdentifier.trim()) {
      throw new ConnectionAuthError(
        FailureReason.PRINCIPAL_REQUIRED,
        config.connectionName,
        "userIdentifier resolved to an empty value for this session",
      );
    }

    const key = `${session.auth?.attributes?.iss ?? config.issuer ?? ""}|${userIdentifier}`;
    return withCache(config, cache, key, () =>
      acquire(config, () =>
        config.zoneClient().impersonate({
          userIdentifier,
          resource: config.resource,
          ...(config.scope ? { scope: config.scope } : {}),
        }),
      ),
    );
  };
}

/**
 * Applies a provider outside turn-build time (rule 6): a route handler, a
 * schedule, or a server tool body passes the session (or `{ auth: null }`)
 * and receives the same headers the turn would have, from the same cache.
 * Named `headersFor` rather than `grant` because it returns headers and
 * throws, where `@keycardai/langchain`'s `grant()` yields an `AccessContext`.
 */
export function headersFor(
  auth: KeycardConnectionAuth,
  session: SessionLike,
): Promise<ConnectionAuthResult> {
  return Promise.resolve(auth(session as SessionInfo));
}

/**
 * The Keycard-principal check: `authenticator` is `keycard`, `principalType`
 * is `user`, and `attributes.iss` is the provider's zone. Another auth
 * policy's principal, or another zone's, never feeds a user pattern. A
 * provider with no `zoneUrl` (an injected `client` alone) cannot check the
 * zone, so it fails closed rather than skip the check.
 */
function requireKeycardUser(
  auth: AuthContext | null | undefined,
  config: ResolvedConnectionConfig,
): AuthContext {
  if (config.issuer === undefined) {
    throw new ConnectionAuthError(
      FailureReason.PRINCIPAL_REQUIRED,
      config.connectionName,
      "this connection acts for a user but has no zoneUrl to check the principal's zone against; " +
        "pass zoneUrl alongside client",
    );
  }
  if (
    auth &&
    auth.authenticator === KEYCARD_AUTHENTICATOR &&
    auth.principalType === "user" &&
    auth.attributes?.iss === config.issuer
  ) {
    return auth;
  }
  throw new ConnectionAuthError(
    FailureReason.PRINCIPAL_REQUIRED,
    config.connectionName,
    "this connection acts for a user, and the session has no Keycard user principal",
  );
}

/**
 * Serves a cached token for `key` until a skew before it expires, minting a
 * new one otherwise. `notAfter` (epoch milliseconds) caps the cached lifetime,
 * so an exchanged token is never served past the subject token it came from.
 */
async function withCache(
  config: ResolvedConnectionConfig,
  cache: Map<string, CachedToken>,
  key: string,
  mint: () => Promise<TokenResponse>,
  notAfter?: number,
): Promise<ConnectionAuthResult> {
  const cached = cache.get(key);
  if (cached && (cached.expiresAt === undefined || cached.expiresAt - config.skewMs > Date.now())) {
    return headers(config, cached.token);
  }
  const response = await mint();
  const zoneExpiry =
    typeof response.expiresIn === "number" && Number.isFinite(response.expiresIn)
      ? Date.now() + response.expiresIn * 1000
      : undefined;
  const expiresAt =
    notAfter === undefined
      ? zoneExpiry
      : zoneExpiry === undefined
        ? notAfter
        : Math.min(zoneExpiry, notAfter);
  cache.set(key, { token: response.accessToken, ...(expiresAt !== undefined ? { expiresAt } : {}) });
  return headers(config, response.accessToken);
}

function headers(config: ResolvedConnectionConfig, token: string): ConnectionAuthResult {
  return { headers: { [config.headerName]: `Bearer ${token}` } };
}

/** Wraps a zone failure as `acquisition_failed`; the message names the reason and resource, never a token. */
async function acquire(
  config: ResolvedConnectionConfig,
  request: () => Promise<TokenResponse>,
): Promise<TokenResponse> {
  try {
    return await request();
  } catch (cause) {
    if (cause instanceof ConnectionAuthError) throw cause;
    const detail = cause instanceof Error ? cause.message : "token acquisition failed";
    throw new ConnectionAuthError(
      FailureReason.ACQUISITION_FAILED,
      config.connectionName,
      `${detail} (resource: ${config.resource})`,
      { cause },
    );
  }
}
