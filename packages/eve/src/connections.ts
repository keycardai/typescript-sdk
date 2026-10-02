import {
  AuthProviderConfigurationError,
  OAuthError,
  TokenType,
  type ClientCredentialsRequest,
  type TokenExchangeRequest,
  type TokenResponse,
} from "@keycardai/oauth";
import { WorkloadIdentityRuntimeError } from "@keycardai/oauth/server";
import type {
  ConnectionPrincipal,
  NonInteractiveAuthorizationDefinition,
  TokenResult,
} from "eve/connections";
import type { SessionContext } from "eve/context";

import {
  expiresAt,
  resolveConnectionConfig,
  type KeycardConnectionOptions,
  type ResolvedConnectionConfig,
} from "./config.js";
import { AuthorizationFailedError, FailureReason } from "./errors.js";
import { subjectTokenExpired } from "./expiry.js";
import { principalKey, readSubjectToken } from "./subjectTokens.js";

/**
 * None of these definitions carry a `displayName`. eve validates an authored
 * connection's `auth` against a closed key list (`completeAuthorization`,
 * `evict`, `getToken`, `principalType`, `startAuthorization`, `vercelConnect`),
 * and a definition carrying any other key fails the build with
 * `The "auth" field Unknown key "displayName"`. The only consumer of the field
 * is eve's `stampChallengeDisplayName`, which resolves
 * `definition.displayName ?? challenge.displayName`, so an interactive
 * definition names itself on the challenge instead (see {@link interactive}),
 * a non-interactive one has no challenge to name, and tools name a provider
 * through `ToolAuthOptions.displayName` at the call site.
 */

/** Options for {@link impersonate}. */
export interface KeycardImpersonateOptions extends KeycardConnectionOptions {
  /**
   * The user the agent acts for. A function receives the connection principal,
   * so a session-scoped identifier can be read from the turn's current auth,
   * or looked up from it (a Slack user id resolved to an email, say).
   */
  userIdentifier: string | ((principal: ConnectionPrincipal) => string | Promise<string>);
  /**
   * The user to act for on turns with no authenticated user, such as
   * schedules. Requires a function `userIdentifier`, and turns the result into
   * a connection auth resolver: a turn whose current auth is a user stays
   * user-scoped and acts for `userIdentifier(principal)`, and any other turn is
   * app-scoped and acts for this identifier.
   *
   * `null`, or a function returning it, makes those turns act as the agent
   * itself, by client credentials as {@link asSelf} does. Only unattended turns
   * can: a user turn whose identifier resolves empty is refused, never served
   * with the agent's authority.
   */
  unattendedUserIdentifier?: string | null | (() => string | null | Promise<string | null>);
}

/** A connection `auth` resolver, as eve calls it with the active turn. */
export type KeycardAuthResolver = (ctx: SessionContext) => NonInteractiveAuthorizationDefinition;

/**
 * Connection auth that runs client credentials under the agent's own identity.
 *
 * App-scoped: eve resolves `{ type: "app" }` and never asks the session for a
 * user, so this works on schedules and subagent turns. No exchange and no
 * impersonation, so nothing about the caller reaches the zone.
 */
export function asSelf(
  options: KeycardConnectionOptions,
): NonInteractiveAuthorizationDefinition {
  const config = resolveConnectionConfig(options, "asSelf");

  return {
    principalType: "app",
    getToken: () => selfToken(config),
  };
}

/** A client-credentials token under the agent's own identity. */
async function selfToken(config: ResolvedConnectionConfig): Promise<TokenResult> {
  const local = config.localToken();
  if (local) return { token: local };

  return tokenResult(
    await acquire(config, null, async () => {
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
 * Connection auth that exchanges the caller's token for a resource token.
 *
 * User-scoped, so eve resolves the principal from the active turn's
 * `ctx.session.auth.current` and fails with `principal_required` before this
 * runs when there is no authenticated user. The subject token exchanged is the
 * one `keycardAuth` verified for that same principal.
 *
 * Nothing here falls back to the agent's authority. A run without a user
 * principal, a turn whose subject token was never retained, and an expired
 * subject token all fail, each with its own reason: `principal_required`,
 * `subject_token_unavailable`, and `subject_token_expired`. The last one is
 * the sign-in signal, decided by a decode-only expiry check so an already
 * dead token never costs an exchange round trip.
 */
export function onBehalfOf(
  options: KeycardConnectionOptions,
): NonInteractiveAuthorizationDefinition {
  const config = resolveConnectionConfig(options, "onBehalfOf");

  return {
    principalType: "user",
    async getToken({ principal }): Promise<TokenResult> {
      requireUser(principal, config.connectionName);

      const subjectToken = readSubjectToken(principal, config.subjectTokens);
      if (!subjectToken) {
        throw new AuthorizationFailedError(config.connectionName, {
          message:
            "No Keycard subject token is retained for this turn's principal. Add " +
            "keycardAuth() to the channel's auth array, or use retainSubjectToken: " +
            '"attributes" when connections run outside the process that authenticated ' +
            "the request.",
          reason: FailureReason.SUBJECT_TOKEN_UNAVAILABLE,
          retryable: false,
        });
      }
      if (subjectTokenExpired(subjectToken)) {
        config.subjectTokens.delete(principalKey(principal));
        throw new AuthorizationFailedError(config.connectionName, {
          message:
            "The Keycard subject token for this turn has expired. Sign in again to continue.",
          reason: FailureReason.SUBJECT_TOKEN_EXPIRED,
          retryable: false,
        });
      }

      return tokenResult(
        await acquire(config, "The signed-in user", async () => {
          let request: TokenExchangeRequest;
          if (config.credential) {
            request = await config.credential.prepareTokenExchangeRequest(
              subjectToken,
              config.resource,
            );
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
      );
    },
  };
}

/**
 * Connection auth that acts for a named user the agent holds no token for.
 *
 * Uses the zone's substitute-user exchange, authenticated by the application
 * credential: no subject token is involved, and the user's grant lives in the
 * zone rather than in this process, so nothing is stored here and a restart
 * never sends the user back through a sign-in. With the default Vercel OIDC
 * credential the deployment holds no secret either.
 *
 * The principal type follows the identifier. A function needs the turn's
 * current user, so the connection is user-scoped and inherits eve's
 * `principal_required` rejection; a fixed identifier needs no caller, so the
 * connection is app-scoped and runs on schedules. Setting
 * `unattendedUserIdentifier` as well returns a resolver that picks between the
 * two per turn, and lets an unattended turn act as the agent itself.
 */
export function impersonate(
  options: KeycardImpersonateOptions & {
    unattendedUserIdentifier: Exclude<KeycardImpersonateOptions["unattendedUserIdentifier"], undefined>;
  },
): KeycardAuthResolver;
export function impersonate(options: KeycardImpersonateOptions): NonInteractiveAuthorizationDefinition;
export function impersonate(
  options: KeycardImpersonateOptions,
): NonInteractiveAuthorizationDefinition | KeycardAuthResolver {
  const config = resolveConnectionConfig(options, "impersonate");
  const { userIdentifier: identifier, unattendedUserIdentifier: unattended } = options;
  for (const fixed of [identifier, unattended]) {
    if (typeof fixed === "string" && !fixed.trim()) {
      throw new AuthProviderConfigurationError(
        "impersonate requires a non-empty user identifier",
      );
    }
  }

  if (typeof identifier === "string") {
    if (unattended !== undefined) {
      throw new AuthProviderConfigurationError(
        "impersonate takes unattendedUserIdentifier only with a function userIdentifier; " +
          "a fixed userIdentifier already runs unattended",
      );
    }
    return impersonation(config, "app", () => identifier);
  }

  const asCaller = impersonation(config, "user", (principal) => {
    requireUser(principal, config.connectionName);
    return identifier(principal);
  });
  if (unattended === undefined) return asCaller;

  const asUnattended = impersonation(
    config,
    "app",
    () => (typeof unattended === "function" ? unattended() : unattended),
    { orSelf: true },
  );
  return (ctx) => (ctx.session?.auth?.current?.principalType === "user" ? asCaller : asUnattended);
}

function impersonation(
  config: ResolvedConnectionConfig,
  principalType: "app" | "user",
  resolveIdentifier: (principal: ConnectionPrincipal) => string | null | Promise<string | null>,
  { orSelf = false }: { orSelf?: boolean } = {},
): NonInteractiveAuthorizationDefinition {
  return {
    principalType,
    async getToken({ principal }): Promise<TokenResult> {
      const resolved = await resolveIdentifier(principal);
      if (resolved === null && orSelf) return selfToken(config);

      const userIdentifier = resolved?.trim();
      if (!userIdentifier) {
        throw new AuthorizationFailedError(config.connectionName, {
          message: "impersonate resolved an empty user identifier for this turn.",
          reason: FailureReason.PRINCIPAL_REQUIRED,
          retryable: false,
        });
      }

      const local = config.localToken();
      if (local) return { token: local };

      return tokenResult(
        await acquire(config, userIdentifier, () =>
          config.zoneClient().impersonate({
            userIdentifier,
            resource: config.resource,
            ...(config.scope ? { scope: config.scope } : {}),
          }),
        ),
      );
    },
  };
}

/**
 * eve rejects a user-scoped connection with no current user before `getToken`
 * runs. This repeats the check with eve's own reason so a factory driven
 * directly, or resolved under an app principal, fails the same way instead of
 * acquiring under the agent's authority.
 */
function requireUser(
  principal: ConnectionPrincipal,
  connectionName: string,
): asserts principal is Extract<ConnectionPrincipal, { type: "user" }> {
  if (principal.type === "user") return;
  throw new AuthorizationFailedError(connectionName, {
    message:
      "This connection acts for a user, and the current turn has no authenticated " +
      "user principal.",
    reason: FailureReason.PRINCIPAL_REQUIRED,
    retryable: false,
  });
}

/**
 * Wraps a zone failure as an eve authorization failure for this connection.
 *
 * A workload credential that could not produce its token is reported as
 * such, since it is a deployment fault no user action fixes. The two
 * failures a user can act on get their own reason and a message
 * written to be relayed as is: a missing grant, fixed by authorizing the
 * resource, and an identifier the zone does not know, which no grant fixes.
 * The second is checked first because the zone reports it as `invalid_grant`
 * too. Everything else stays `acquisition_failed` with the zone's own message.
 *
 * `user` names who the token is for, or is null when the agent acts as itself.
 */
async function acquire(
  config: ResolvedConnectionConfig,
  user: string | null,
  request: () => Promise<TokenResponse>,
): Promise<TokenResponse> {
  try {
    return await request();
  } catch (cause) {
    const detail = cause instanceof Error ? cause.message : "Token acquisition failed";
    const fail = (reason: string, message: string): never => {
      throw new AuthorizationFailedError(config.connectionName, {
        message,
        reason,
        retryable: false,
      });
    };

    if (cause instanceof WorkloadIdentityRuntimeError) {
      fail(FailureReason.WORKLOAD_IDENTITY_UNAVAILABLE, detail);
    }
    if (user !== null && isUnknownUser(detail)) {
      fail(
        FailureReason.UNKNOWN_USER,
        `${user} is not a user in this Keycard zone, so there is no grant to act ` +
          `under for ${config.resource}. Authorizing the resource will not help until the ` +
          `identifier matches a zone user exactly. Zone said: ${detail}`,
      );
    }
    if (needsUserAuthorization(cause, detail)) {
      fail(
        FailureReason.USER_AUTHORIZATION_REQUIRED,
        user !== null
          ? `${user} has not authorized ${config.resource} yet. Access runs under ` +
              `their own grant, so there is nothing else to fall back to. ` +
              `${config.authorizationHint} Zone said: ${detail}`
          : `${config.resource} accepts only per-user grants, so the agent cannot reach it as ` +
              `itself. Act for a user with impersonate or onBehalfOf, or permit the ` +
              `application on this resource in the zone. Zone said: ${detail}`,
      );
    }
    return fail(FailureReason.ACQUISITION_FAILED, detail);
  }
}

/** OAuth codes the zone uses for "this resource needs a user's own grant". */
const USER_AUTHORIZATION_CODES = new Set([
  "insufficient_authorization",
  "authorization_required",
  "user_authorization_required",
]);

function needsUserAuthorization(cause: unknown, detail: string): boolean {
  if (cause instanceof OAuthError && USER_AUTHORIZATION_CODES.has(cause.errorCode)) return true;
  // The prose varies ("User authorization is required for resource ..."), so
  // match it independent of word order.
  const text = detail.toLowerCase();
  return (
    text.includes("cannot be accessed with client credentials") ||
    (text.includes("user authorization") && text.includes("requir"))
  );
}

/** Text only: the zone's code for an unknown identifier is the generic `invalid_grant`. */
function isUnknownUser(detail: string): boolean {
  return detail.toLowerCase().includes("user not found");
}

function tokenResult(response: TokenResponse): TokenResult {
  const expiry = expiresAt(response.expiresIn);
  return {
    token: response.accessToken,
    ...(expiry !== undefined ? { expiresAt: expiry } : {}),
  };
}
