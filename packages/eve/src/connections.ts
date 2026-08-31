import {
  AuthProviderConfigurationError,
  TokenType,
  type ClientCredentialsRequest,
  type TokenExchangeRequest,
  type TokenResponse,
} from "@keycardai/oauth";
import type {
  ConnectionPrincipal,
  NonInteractiveAuthorizationDefinition,
  TokenResult,
} from "eve/connections";

import { expiresAt, resolveConnectionConfig, type KeycardConnectionOptions } from "./config.js";
import { AuthorizationFailedError, FailureReason } from "./errors.js";
import { subjectTokenExpired } from "./expiry.js";
import { principalKey, readSubjectToken } from "./subjectTokens.js";

/** Options for {@link impersonate}. */
export interface KeycardImpersonateOptions extends KeycardConnectionOptions {
  /**
   * The user the agent acts for. A function receives the connection principal,
   * so a session-scoped identifier can be read from the turn's current auth.
   */
  userIdentifier: string | ((principal: ConnectionPrincipal) => string);
}

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
    displayName: config.connectionName,
    async getToken(): Promise<TokenResult> {
      const request: ClientCredentialsRequest = {
        resource: config.resource,
        ...(config.scope ? { scope: config.scope } : {}),
        ...(await config.clientAuthFields()),
      };
      return tokenResult(
        await acquire(config.connectionName, () =>
          config.zoneClient().clientCredentialsGrant(request),
        ),
      );
    },
  };
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
    displayName: config.connectionName,
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

      return tokenResult(
        await acquire(config.connectionName, () => config.zoneClient().exchangeToken(request)),
      );
    },
  };
}

/**
 * Connection auth that acts for a named user the agent holds no token for.
 *
 * Uses the zone's substitute-user exchange, authenticated by the application
 * credential: no subject token is involved, so this is the pattern for
 * back-office and batch work rather than for a user's own request.
 *
 * The principal type follows the identifier. A function needs the turn's
 * current user, so the connection is user-scoped and inherits eve's
 * `principal_required` rejection; a fixed identifier needs no caller, so the
 * connection is app-scoped and runs on schedules.
 */
export function impersonate(
  options: KeycardImpersonateOptions,
): NonInteractiveAuthorizationDefinition {
  const config = resolveConnectionConfig(options, "impersonate");
  const identifier = options.userIdentifier;
  if (typeof identifier === "string" && !identifier.trim()) {
    throw new AuthProviderConfigurationError(
      "impersonate requires a non-empty user identifier",
    );
  }

  return {
    principalType: typeof identifier === "function" ? "user" : "app",
    displayName: config.connectionName,
    async getToken({ principal }): Promise<TokenResult> {
      let userIdentifier: string;
      if (typeof identifier === "function") {
        requireUser(principal, config.connectionName);
        userIdentifier = identifier(principal);
      } else {
        userIdentifier = identifier;
      }
      if (!userIdentifier || !userIdentifier.trim()) {
        throw new AuthorizationFailedError(config.connectionName, {
          message: "impersonate resolved an empty user identifier for this turn.",
          reason: FailureReason.PRINCIPAL_REQUIRED,
          retryable: false,
        });
      }

      return tokenResult(
        await acquire(config.connectionName, () =>
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

/** Wraps a zone failure as an eve authorization failure for this connection. */
async function acquire(
  connectionName: string,
  request: () => Promise<TokenResponse>,
): Promise<TokenResponse> {
  try {
    return await request();
  } catch (cause) {
    throw new AuthorizationFailedError(connectionName, {
      message: cause instanceof Error ? cause.message : "Token acquisition failed",
      reason: FailureReason.ACQUISITION_FAILED,
      retryable: false,
    });
  }
}

function tokenResult(response: TokenResponse): TokenResult {
  const expiry = expiresAt(response.expiresIn);
  return {
    token: response.accessToken,
    ...(expiry !== undefined ? { expiresAt: expiry } : {}),
  };
}
