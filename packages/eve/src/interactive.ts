import {
  AuthProviderConfigurationError,
  AuthorizationDeniedError,
  beginAuthorization,
  completeAuthorization,
  fetchAuthorizationServerMetadata,
  registerClient,
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
 *
 * `clientId` is journaled because it is not necessarily the same value across
 * attempts: under per-attempt registration each authorization runs as its own
 * client, and the code can only be redeemed by the client the authorization
 * request was made with. Nothing secret is journaled — registered clients are
 * public and PKCE-bound; see {@link interactive}.
 */
export interface KeycardResumeState {
  readonly state: string;
  readonly codeVerifier: string;
  readonly resources: readonly string[];
  readonly callbackUrl: string;
  readonly clientId: string;
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

/** What one authorization attempt needs its own OAuth client for. */
export interface RegisterAttemptClientOptions {
  /** eve's callback URL for this attempt. The client's only redirect URI. */
  readonly redirectUri: string;
  /** Name the zone shows on the consent screen. */
  readonly clientName?: string;
  readonly scopes?: readonly string[];
}

/** A client the authorization server issued for one attempt. */
export interface RegisteredClient {
  readonly clientId: string;
  /**
   * Only ever set by a server that ignored the public-client registration
   * request. {@link interactive} refuses such a client rather than journaling
   * a secret into eve's durable state.
   */
  readonly clientSecret?: string;
}

/** The web-flow calls this adapter makes, as one seam for tests. */
export interface WebAppFlow {
  begin(options: BeginAuthorizationOptions): Promise<AuthorizationRedirect>;
  complete(options: CompleteAuthorizationOptions): Promise<TokenResponse>;
  /**
   * Registers the client for one attempt (RFC 7591). Required when no static
   * `clientId` is configured, and unused when one is.
   */
  register?(options: RegisterAttemptClientOptions): Promise<RegisteredClient>;
}

export interface KeycardInteractiveOptions {
  /** The resource URL the authorization is scoped to. */
  resource: string;
  /** Keycard zone URL (issuer). Required unless `flow` is given. */
  zoneUrl?: string;
  /**
   * OAuth client the browser flow runs as.
   *
   * OMIT THIS unless the client's registered redirect URIs already cover eve's
   * callback. eve mints a fresh callback URL per attempt — the route is
   * `/eve/v1/connections/:name/callback/:attemptId/:token` — while RFC 9700
   * requires the authorization server to match `redirect_uri` by exact string
   * comparison. A statically registered client therefore cannot name the URL
   * the next attempt will use, and the request is rejected. Leaving this unset
   * registers the client per attempt instead, which is the only arrangement
   * that satisfies both.
   *
   * A Keycard application `identifier` is NOT a client id. Zones identify
   * clients by Client ID Metadata Document — an HTTPS URL with a path that
   * serves the client's metadata — so a value like `urn:app:my-agent` fails
   * with `Unsupported client identifier prefix: urn`.
   */
  clientId?: string;
  /** Client secret, for a confidential static client. Public clients omit it. */
  clientSecret?: string;
  /**
   * Name shown on the zone's consent screen for a per-attempt client.
   * Defaults to `connectionName`.
   */
  clientName?: string;
  /**
   * Initial access token (RFC 7591 §3.1) for a zone whose registration
   * endpoint is authenticated. Unset for an open registration endpoint.
   */
  initialAccessToken?: string;
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
 * THE CLIENT IS REGISTERED PER ATTEMPT unless `clientId` says otherwise, and
 * that is not an optimization — it is what makes the flow work at all. eve
 * mints a fresh callback URL for every attempt, carrying the attempt id and a
 * run token in its path, while RFC 9700 requires the authorization server to
 * match `redirect_uri` against the client's registered list by exact string
 * comparison. No fixed registration can name a URL that is generated later, so
 * a static client and a dynamic callback cannot both hold. Registering the
 * client alongside the callback it belongs to resolves it: each attempt gets a
 * public, PKCE-bound client whose one redirect URI is the one URL that attempt
 * will return to.
 *
 * Each attempt therefore leaves a client record in the zone. They are public,
 * hold no secret, and are bound to a callback URL that is single-use, but they
 * do accumulate; a server that returns `registration_client_uri` and
 * `registration_access_token` allows RFC 7592 deletion once a grant settles.
 *
 * Discovery is memoized per definition, so the first authorization pays the
 * metadata round trip and later ones do not. Registration is not memoized —
 * the redirect URI it binds is different every time.
 */
export function interactive(
  options: KeycardInteractiveOptions,
): InteractiveAuthorizationDefinition<KeycardResumeState> {
  if (!options.resource || !options.resource.trim()) {
    throw new AuthProviderConfigurationError("interactive requires a resource URL");
  }
  if (!options.flow && !options.zoneUrl) {
    throw new AuthProviderConfigurationError("interactive requires zoneUrl, or an injected flow");
  }

  const connectionName = options.connectionName ?? options.resource;
  const tokens = options.tokens ?? memoryAuthorizedTokenStore();
  const flow =
    options.flow ??
    zoneWebAppFlow(options.zoneUrl!, {
      ...(options.initialAccessToken !== undefined
        ? { initialAccessToken: options.initialAccessToken }
        : {}),
    });
  const staticClientId = options.clientId ?? "";
  const clientName = options.clientName ?? connectionName;
  const resources = [options.resource, ...(options.additionalResources ?? [])];
  const scopes = splitScopes(options.requestScopes);

  if (!staticClientId && !flow.register) {
    throw new AuthProviderConfigurationError(
      "interactive was given no clientId, so it registers a client per attempt, but the " +
        "injected flow has no register()",
    );
  }

  /**
   * The client this attempt runs as: the configured one, or a fresh public
   * client whose single redirect URI is this attempt's callback.
   */
  const clientForAttempt = async (callbackUrl: string): Promise<string> => {
    if (staticClientId) return staticClientId;
    let registered: RegisteredClient;
    try {
      registered = await flow.register!({
        redirectUri: callbackUrl,
        clientName,
        ...(scopes.length > 0 ? { scopes } : {}),
      });
    } catch (cause) {
      throw new AuthorizationFailedError(connectionName, {
        message:
          cause instanceof Error
            ? `Registering the OAuth client for this authorization failed: ${cause.message}`
            : "Registering the OAuth client for this authorization failed",
        reason: FailureReason.ACQUISITION_FAILED,
        retryable: true,
      });
    }
    if (registered.clientSecret) {
      throw new AuthorizationFailedError(connectionName, {
        message:
          "The authorization server issued a confidential client for an authorization " +
          "registered as public. Redeeming it would mean journaling a client secret into " +
          "eve's durable resume state, so the attempt was abandoned instead. Configure a " +
          "static clientId for this connection.",
        reason: FailureReason.ACQUISITION_FAILED,
        retryable: false,
      });
    }
    return registered.clientId;
  };

  return {
    principalType: "user",
    /**
     * NO definition-level `displayName`. eve validates an authored connection's
     * `auth` against a closed key list (`completeAuthorization`, `evict`,
     * `getToken`, `principalType`, `startAuthorization`, `vercelConnect`) that
     * omits it, so setting it here fails the BUILD with
     * `The "auth" field Unknown key "displayName"` for every interactive
     * connection. The name still reaches the sign-in prompt: it rides on the
     * challenge below, and eve's `stampChallengeDisplayName` resolves
     * `definition.displayName ?? challenge.displayName`. The definition-level
     * field was only ever a precedence override of a value already carried.
     */
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
      const attemptClientId = await clientForAttempt(callbackUrl);
      const redirect = await flow.begin({
        clientId: attemptClientId,
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
          clientId: attemptClientId,
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
          // The attempt's own client. Falls back to the configured one for a
          // resume journaled before this field existed.
          clientId: resume.clientId || staticClientId,
          redirectUri: resume.callbackUrl || callbackUrl,
          // Only a static client can be confidential; a per-attempt client is
          // always public, so there is no secret to send.
          ...(staticClientId && options.clientSecret
            ? { clientSecret: options.clientSecret }
            : {}),
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
function zoneWebAppFlow(
  issuer: string,
  options: { initialAccessToken?: string } = {},
): WebAppFlow {
  let metadata: Promise<OAuthAuthorizationServerMetadata> | undefined;
  const discover = (): Promise<OAuthAuthorizationServerMetadata> => {
    if (!metadata) metadata = fetchAuthorizationServerMetadata(issuer);
    return metadata;
  };
  return {
    async begin(beginOptions) {
      return beginAuthorization(issuer, { ...beginOptions, metadata: await discover() });
    },
    async complete(completeOptions) {
      return completeAuthorization(issuer, { ...completeOptions, metadata: await discover() });
    },
    /**
     * One public, PKCE-bound client per authorization, holding the single
     * redirect URI that attempt will actually come back to.
     *
     * `token_endpoint_auth_method: "none"` is what keeps the resume state free
     * of credentials: a public client has no secret to journal, and the code is
     * bound to the PKCE verifier instead. `refresh_token` is requested so a
     * long-lived grant can be renewed without sending the user back through the
     * browser.
     */
    async register({ redirectUri, clientName, scopes }) {
      const registered = await registerClient(
        issuer,
        {
          ...(clientName !== undefined ? { clientName } : {}),
          redirectUris: [redirectUri],
          grantTypes: ["authorization_code", "refresh_token"],
          responseTypes: ["code"],
          tokenEndpointAuthMethod: "none",
          ...(scopes && scopes.length > 0 ? { scope: scopes.join(" ") } : {}),
        },
        options.initialAccessToken !== undefined
          ? { initialAccessToken: options.initialAccessToken }
          : undefined,
      );
      return {
        clientId: registered.clientId,
        ...(registered.clientSecret !== undefined
          ? { clientSecret: registered.clientSecret }
          : {}),
      };
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
