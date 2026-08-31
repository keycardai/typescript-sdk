import {
  AuthProviderConfigurationError,
  AuthorizationDeniedError,
  beginAuthorization,
  completeAuthorization,
  fetchAuthorizationServerMetadata,
  StateMismatchError,
  type AuthorizationRedirect,
  type BeginAuthorizationOptions,
  type CompleteAuthorizationOptions,
  type OAuthAuthorizationServerMetadata,
  type TokenResponse,
} from "@keycardai/oauth";
import type {
  ConnectionPrincipal,
  InteractiveAuthorizationDefinition,
  JsonValue,
  TokenResult,
} from "eve/connections";

import { expiresAt } from "./config.js";
import {
  AuthorizationFailedError,
  AuthorizationRequiredError,
  FailureReason,
} from "./errors.js";
import { principalKey } from "./subjectTokens.js";

/**
 * The state journaled between eve's begin and callback steps.
 *
 * Every field is JSON, so the value satisfies eve's `JsonValue` bound and
 * survives the durable step boundary the park crosses.
 */
export interface KeycardResumeState {
  readonly state: string;
  readonly codeVerifier: string;
  readonly resources: readonly string[];
  readonly callbackUrl: string;
  readonly [key: string]: JsonValue;
}

/** A token this package minted for one principal, plus its advisory expiry. */
export interface AuthorizedToken {
  readonly token: string;
  readonly expiresAt?: number;
  readonly providerSubject?: string;
}

/**
 * Where completed authorizations live between turns.
 *
 * eve caches a resolved bearer for the duration of a step, and reruns
 * `getToken` after that. This store is what makes a second step reuse the
 * grant a user already completed instead of parking the turn again. The
 * default is process-local, so a fresh process re-parks rather than
 * resurrecting a credential from durable state.
 */
export interface AuthorizedTokenStore {
  get(key: string): AuthorizedToken | undefined;
  set(key: string, token: AuthorizedToken): void;
  delete(key: string): void;
}

/** The two web-flow calls this adapter makes, as one seam for tests. */
export interface WebAppFlow {
  begin(options: BeginAuthorizationOptions): Promise<AuthorizationRedirect>;
  complete(options: CompleteAuthorizationOptions): Promise<TokenResponse>;
}

export interface KeycardInteractiveOptions {
  /** The resource URL the authorization is scoped to. */
  resource: string;
  /** Keycard zone URL (issuer). Required unless `flow` is given. */
  zoneUrl?: string;
  /** OAuth client the browser flow runs as. Required unless `flow` is given. */
  clientId?: string;
  /** Client secret, for a confidential client. Public clients omit it. */
  clientSecret?: string;
  /** Scopes requested in the authorization request. */
  requestScopes?: string | readonly string[];
  /** Extra resources authorized alongside `resource`. */
  additionalResources?: readonly string[];
  /** Name used in error messages and eve's authorization events. */
  connectionName?: string;
  /** Store for completed authorizations. Defaults to a process-local store. */
  tokens?: AuthorizedTokenStore;
  /** Web-flow seam. Replaces the zone calls, so tests take no network. */
  flow?: WebAppFlow;
}

/**
 * Interactive connection auth backed by the zone's web authorization flow.
 *
 * The three callbacks eve drives:
 *
 * - `getToken` returns a token only when this package holds one for the
 *   principal. Otherwise it throws `ConnectionAuthorizationRequiredError`, and
 *   eve emits `authorization.required`, runs `startAuthorization` in a durable
 *   step, and parks the turn on its own callback webhook.
 * - `startAuthorization` begins the authorization-code flow with PKCE for the
 *   connection's resources, against eve's minted callback URL, and returns the
 *   challenge URL plus the `state` and verifier as resume state.
 * - `completeAuthorization` redeems the callback against the journaled resume
 *   state and hands eve the token.
 *
 * Resuming without a completed authorization cannot yield a credential.
 * `getToken` is the only path that returns a token and it reads the store,
 * which only `completeAuthorization` writes; a denied, mismatched, or failed
 * callback writes nothing. So a resumed turn either finds a real grant or
 * throws `Required` again and parks. eve's own settlement makes that terminal
 * rather than an endless loop: it settles each parked authorization once, and
 * a `Required` thrown after a completed authorization ends the tool call.
 *
 * Discovery is memoized per definition, so the first authorization pays the
 * metadata round trip and later ones do not.
 */
export function interactive(
  options: KeycardInteractiveOptions,
): InteractiveAuthorizationDefinition<KeycardResumeState> {
  if (!options.resource || !options.resource.trim()) {
    throw new AuthProviderConfigurationError("interactive requires a resource URL");
  }
  if (!options.flow && (!options.zoneUrl || !options.clientId)) {
    throw new AuthProviderConfigurationError(
      "interactive requires zoneUrl and clientId, or an injected flow",
    );
  }

  const connectionName = options.connectionName ?? options.resource;
  const tokens = options.tokens ?? memoryAuthorizedTokenStore();
  const flow = options.flow ?? zoneWebAppFlow(options.zoneUrl!);
  const clientId = options.clientId ?? "";
  const resources = [options.resource, ...(options.additionalResources ?? [])];
  const scopes = splitScopes(options.requestScopes);

  return {
    principalType: "user",
    displayName: connectionName,
    async getToken({ principal }): Promise<TokenResult> {
      const key = storeKey(principal, connectionName);
      const held = tokens.get(key);
      if (!held) {
        throw new AuthorizationRequiredError(connectionName);
      }
      return toTokenResult(held);
    },
    async startAuthorization({ principal, callbackUrl }) {
      requireUser(principal, connectionName);
      const redirect = await flow.begin({
        clientId,
        redirectUri: callbackUrl,
        resources,
        ...(scopes.length > 0 ? { scopes } : {}),
      });
      return {
        challenge: { url: redirect.url, displayName: connectionName },
        resume: {
          state: redirect.state,
          codeVerifier: redirect.codeVerifier,
          resources: redirect.resources,
          callbackUrl,
        },
      };
    },
    async completeAuthorization({ principal, callbackUrl, resume, callback }) {
      requireUser(principal, connectionName);
      if (!resume) {
        throw new AuthorizationFailedError(connectionName, {
          message:
            "The authorization callback arrived without the state journaled at the " +
            "begin step, so it cannot be redeemed.",
          reason: FailureReason.INVALID_CALLBACK,
          retryable: false,
        });
      }

      let response: TokenResponse;
      try {
        response = await flow.complete({
          callbackParams: { ...callback.params },
          state: resume.state,
          codeVerifier: resume.codeVerifier,
          clientId,
          redirectUri: resume.callbackUrl || callbackUrl,
          ...(options.clientSecret ? { clientSecret: options.clientSecret } : {}),
        });
      } catch (cause) {
        throw new AuthorizationFailedError(connectionName, {
          message: cause instanceof Error ? cause.message : "Authorization failed",
          reason:
            cause instanceof AuthorizationDeniedError
              ? FailureReason.ACCESS_DENIED
              : cause instanceof StateMismatchError
                ? FailureReason.INVALID_CALLBACK
                : FailureReason.ACQUISITION_FAILED,
          retryable: false,
        });
      }

      const expiry = expiresAt(response.expiresIn);
      const token: AuthorizedToken = {
        token: response.accessToken,
        ...(expiry !== undefined ? { expiresAt: expiry } : {}),
      };
      tokens.set(storeKey(principal, connectionName), token);
      return toTokenResult(token);
    },
    /**
     * eve calls this after a rejected bearer, so the next `getToken` parks the
     * turn for a fresh grant instead of handing back the same dead token.
     */
    evict({ principal }) {
      tokens.delete(storeKey(principal, connectionName));
    },
  };
}

/** A process-local store that drops entries at their advisory expiry. */
export function memoryAuthorizedTokenStore(): AuthorizedTokenStore {
  const tokens = new Map<string, AuthorizedToken>();
  return {
    get(key) {
      const held = tokens.get(key);
      if (!held) return undefined;
      if (held.expiresAt !== undefined && held.expiresAt <= Date.now()) {
        tokens.delete(key);
        return undefined;
      }
      return held;
    },
    set(key, token) {
      tokens.set(key, token);
    },
    delete(key) {
      tokens.delete(key);
    },
  };
}

/** The default flow: the zone's web-app endpoints, with discovery memoized. */
function zoneWebAppFlow(issuer: string): WebAppFlow {
  let metadata: Promise<OAuthAuthorizationServerMetadata> | undefined;
  const discover = (): Promise<OAuthAuthorizationServerMetadata> => {
    if (!metadata) metadata = fetchAuthorizationServerMetadata(issuer);
    return metadata;
  };
  return {
    async begin(options) {
      return beginAuthorization(issuer, { ...options, metadata: await discover() });
    },
    async complete(options) {
      return completeAuthorization(issuer, { ...options, metadata: await discover() });
    },
  };
}

function storeKey(principal: ConnectionPrincipal, connectionName: string): string {
  if (principal.type !== "user") return `${connectionName}|app`;
  return `${connectionName}|${principalKey(principal)}`;
}

function toTokenResult(token: AuthorizedToken): TokenResult {
  return {
    token: token.token,
    ...(token.expiresAt !== undefined ? { expiresAt: token.expiresAt } : {}),
    ...(token.providerSubject !== undefined
      ? { providerSubject: token.providerSubject }
      : {}),
  };
}

function requireUser(principal: ConnectionPrincipal, connectionName: string): void {
  if (principal.type === "user") return;
  throw new AuthorizationFailedError(connectionName, {
    message:
      "Interactive authorization needs a user principal, and the current turn has " +
      "no authenticated user.",
    reason: FailureReason.PRINCIPAL_REQUIRED,
    retryable: false,
  });
}

function splitScopes(scopes: string | readonly string[] | undefined): string[] {
  if (scopes === undefined) return [];
  return Array.isArray(scopes) ? [...scopes] : (scopes as string).split(" ").filter(Boolean);
}
