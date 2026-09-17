import {
  AuthProviderConfigurationError,
  AuthorizationDeniedError,
  beginAuthorization,
  completeAuthorization,
  fetchAuthorizationServerMetadata,
  refreshAuthorization,
  RefreshGrantError,
  registerClient,
  StateMismatchError,
  type AuthorizationRedirect,
  type BeginAuthorizationOptions,
  type CompleteAuthorizationOptions,
  type OAuthAuthorizationServerMetadata,
  type RefreshAuthorizationOptions,
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

/** A grant is refreshed once it is this close to its advisory expiry. */
const REFRESH_SKEW_MS = 60_000;

/**
 * The state journaled between eve's begin and callback steps.
 *
 * Every field is JSON, so the value satisfies eve's `JsonValue` bound and
 * survives the durable step boundary the park crosses. `clientId` is journaled
 * because each attempt may run as its own registered client, and only that
 * client can redeem the code. Nothing secret is journaled: registered clients
 * are public and PKCE-bound (see {@link interactive}).
 */
export interface KeycardResumeState {
  readonly state: string;
  readonly codeVerifier: string;
  readonly resources: readonly string[];
  readonly callbackUrl: string;
  readonly clientId: string;
  readonly [key: string]: JsonValue;
}

/**
 * A completed authorization for one principal.
 *
 * `resources` and `scopes` are what the zone granted, and decide which
 * connections the grant serves. `clientId` is the client the grant was issued
 * to, and the client a refresh runs as. `id` is stable across refreshes, so a
 * store can replace the rotated pair in place.
 */
export interface AuthorizedGrant {
  readonly id: string;
  readonly accessToken: string;
  readonly expiresAt?: number;
  readonly refreshToken?: string;
  readonly clientId: string;
  readonly resources: readonly string[];
  readonly scopes: readonly string[];
}

/**
 * Where completed grants live between turns, keyed by principal.
 *
 * eve caches a resolved bearer for the duration of a step and reruns
 * `getToken` after that; this store is what makes a later step reuse the grant
 * a user already completed instead of parking again. `put` with an `id` the
 * store already holds replaces that grant. The default is process-local, so a
 * fresh process re-parks. A durable implementation (Redis, Upstash Redis) keeps the
 * grant, refresh token included, at rest in that backend; eve's session
 * attributes are never used, so no credential enters eve's durable state.
 */
export interface GrantStore {
  list(principal: string): Promise<readonly AuthorizedGrant[]>;
  put(principal: string, grant: AuthorizedGrant): Promise<void>;
  remove(principal: string, grantId: string): Promise<void>;
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
  /**
   * Refreshes a grant at the token endpoint. When absent, a grant near expiry
   * parks for a fresh sign-in instead.
   */
  refresh?(options: RefreshAuthorizationOptions): Promise<TokenResponse>;
}

export interface KeycardInteractiveOptions {
  /** The resource URL the authorization is scoped to. */
  resource: string;
  /** Keycard zone URL (issuer). Required unless `flow` is given. */
  zoneUrl?: string;
  /**
   * OAuth client the browser flow runs as.
   *
   * Leave this unset unless the client's registered redirect URIs already
   * cover eve's callback. eve mints a fresh callback URL per attempt
   * (`/eve/v1/connections/:name/callback/:attemptId/:token`) while RFC 9700
   * requires the authorization server to match `redirect_uri` by exact string
   * comparison, so a statically registered client cannot name the URL the next
   * attempt will use. Unset, the client is registered per attempt instead.
   *
   * A Keycard application `identifier` is not a client id. Zones identify
   * clients by Client ID Metadata Document, an HTTPS URL with a path that
   * serves the client's metadata, so a value like `urn:app:my-agent` fails
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
   * Initial access token (RFC 7591 section 3.1) for a zone whose registration
   * endpoint is authenticated. Unset for an open registration endpoint.
   */
  initialAccessToken?: string;
  /**
   * Scopes requested in the authorization request, and the scopes a stored
   * grant must cover to serve this connection.
   */
  requestScopes?: string | readonly string[];
  /**
   * Extra resources authorized alongside `resource`. The resulting grant
   * serves every connection whose resource it covers.
   */
  additionalResources?: readonly string[];
  /**
   * Name used in the challenge, error messages and eve's authorization
   * events. Display text only, never a store key; two definitions in one
   * process may not share it.
   */
  connectionName?: string;
  /** Store for completed grants. Defaults to a process-local store. */
  tokens?: GrantStore;
  /** Web-flow seam. Replaces the zone calls, so tests take no network. */
  flow?: WebAppFlow;
}

/** Connection names taken by `interactive()` definitions in this process. */
const definedConnectionNames = new Set<string>();

/** Forgets every defined connection name. For tests that define many. */
export function resetInteractiveDefinitions(): void {
  definedConnectionNames.clear();
}

/**
 * Interactive connection auth backed by the zone's web authorization flow.
 *
 * The three callbacks eve drives:
 *
 * - `getToken` returns a token when the store holds a grant for the principal
 *   whose resources cover this connection's resource and whose scopes cover
 *   `requestScopes`, refreshing it first when it is near expiry and holds a
 *   refresh token. Otherwise it throws `ConnectionAuthorizationRequiredError`,
 *   and eve emits `authorization.required`, runs `startAuthorization` in a
 *   durable step, and parks the turn on its own callback webhook.
 * - `startAuthorization` registers the attempt's client, begins the
 *   authorization-code flow with PKCE for the connection's resources against
 *   eve's minted callback URL, and returns the challenge URL plus the state,
 *   verifier, resources, callback URL and client id as resume state.
 * - `completeAuthorization` redeems the callback as the journaled client and
 *   stores the resulting grant.
 *
 * Resuming without a completed authorization cannot yield a credential: only
 * `completeAuthorization` writes the store, and a denied, mismatched, or failed
 * callback writes nothing, so a resumed turn either finds a real grant or parks
 * again. eve settles each parked authorization once, so that is terminal rather
 * than a loop.
 *
 * The client is registered per attempt unless `clientId` is set. eve mints a
 * fresh callback URL for every attempt, while RFC 9700 requires the
 * authorization server to match `redirect_uri` against the client's registered
 * list by exact string comparison, so no fixed registration can name a URL that
 * is generated later. Each attempt therefore gets a public, PKCE-bound client
 * whose one redirect URI is the callback that attempt returns to. Those client
 * records accumulate in the zone; a server that returns
 * `registration_client_uri` and `registration_access_token` allows RFC 7592
 * deletion once a grant settles.
 *
 * Grants are keyed by principal, never by `connectionName`, so two connections
 * never share a token through a shared name and `evict` on one cannot clear the
 * other's grant. A grant obtained with `additionalResources` serves every
 * connection whose resource it covers, so listing the agent's resources on one
 * connection yields one sign-in.
 *
 * Discovery is memoized per definition. Registration is not, because the
 * redirect URI it binds is different every time.
 */
export function interactive(
  options: KeycardInteractiveOptions,
): InteractiveAuthorizationDefinition<KeycardResumeState> {
  if (!options.resource || !options.resource.trim()) {
    throw new AuthProviderConfigurationError(
      "interactive requires a resource URL",
    );
  }
  if (!options.flow && !options.zoneUrl) {
    throw new AuthProviderConfigurationError(
      "interactive requires zoneUrl, or an injected flow",
    );
  }

  const connectionName = options.connectionName ?? options.resource;
  if (definedConnectionNames.has(connectionName)) {
    throw new AuthProviderConfigurationError(
      `interactive connectionName "${connectionName}" is already defined in this process. ` +
        "The name is display text, not a token key, so give each connection its own.",
    );
  }
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
  definedConnectionNames.add(connectionName);

  const covers = (grant: AuthorizedGrant): boolean =>
    grant.resources.includes(options.resource) &&
    scopes.every((scope) => grant.scopes.includes(scope));

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

  /** A per-attempt client is public; only the static client can hold a secret. */
  const secretFor = (
    clientId: string,
  ): { clientSecret: string } | Record<never, never> =>
    staticClientId && clientId === staticClientId && options.clientSecret
      ? { clientSecret: options.clientSecret }
      : {};

  /**
   * Refreshes a near-expiry grant as the client it was issued to. A refused
   * refresh drops the grant so the caller parks for a fresh sign-in.
   */
  const refreshGrant = async (
    principal: string,
    grant: AuthorizedGrant & { refreshToken: string },
  ): Promise<AuthorizedGrant> => {
    let response: TokenResponse;
    try {
      response = await flow.refresh!({
        refreshToken: grant.refreshToken,
        clientId: grant.clientId,
        resources: grant.resources,
        ...(grant.scopes.length > 0 ? { scopes: grant.scopes } : {}),
        ...secretFor(grant.clientId),
      });
    } catch (cause) {
      if (
        cause instanceof RefreshGrantError &&
        cause.errorCode === "invalid_grant"
      ) {
        // A concurrent step may have rotated this grant first, in which case
        // the refresh token we sent is the stale one and the stored grant is
        // the good one.
        const current = (await tokens.list(principal)).find(
          (candidate) => candidate.id === grant.id,
        );
        if (current && current.refreshToken !== grant.refreshToken) {
          return current;
        }
        await tokens.remove(principal, grant.id);
        throw new AuthorizationRequiredError(connectionName, {
          message:
            `Connection "${connectionName}" requires authorization: the zone refused to ` +
            `refresh the grant (${cause.message}).`,
        });
      }
      throw new AuthorizationFailedError(connectionName, {
        message:
          cause instanceof Error
            ? `Refreshing the grant failed: ${cause.message}`
            : "Refreshing the grant failed",
        reason: FailureReason.ACQUISITION_FAILED,
        retryable: cause instanceof RefreshGrantError ? cause.retryable : true,
      });
    }
    const rotated = grantFromResponse(response, {
      id: grant.id,
      clientId: grant.clientId,
      resources: grant.resources,
      scopes: grant.scopes,
      // A server that rotates nothing leaves the old refresh token valid.
      refreshToken: grant.refreshToken,
    });
    await tokens.put(principal, rotated);
    return rotated;
  };

  return {
    principalType: "user",
    /**
     * No definition-level `displayName`: eve validates an authored connection's
     * `auth` against a closed key list (`completeAuthorization`, `evict`,
     * `getToken`, `principalType`, `startAuthorization`, `vercelConnect`) that
     * omits it. The name rides on the challenge instead, where eve's
     * `stampChallengeDisplayName` falls back to it.
     */
    async getToken({ principal }): Promise<TokenResult> {
      const key = storeKey(principal);
      const now = Date.now();
      const held = (await tokens.list(key)).filter(covers);
      // A grant is usable while its access token is live or while it holds a
      // refresh token that can mint a new one; an expired grant with no refresh
      // token is dead.
      const usable = held.filter((candidate) => !dead(candidate, now));
      let grant =
        usable.find((candidate) => !expired(candidate, now)) ?? usable[0];
      if (!grant) {
        await Promise.all(held.map((stale) => tokens.remove(key, stale.id)));
        throw new AuthorizationRequiredError(connectionName);
      }
      if (nearExpiry(grant, now) && grant.refreshToken && flow.refresh) {
        grant = await refreshGrant(key, {
          ...grant,
          refreshToken: grant.refreshToken,
        });
      } else if (expired(grant, now)) {
        // Expired, and this flow cannot refresh it.
        await tokens.remove(key, grant.id);
        throw new AuthorizationRequiredError(connectionName);
      }
      return toTokenResult(grant);
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

      // The attempt's own client, falling back to the configured one for a
      // resume journaled before clientId existed.
      const clientId = resume.clientId || staticClientId;
      let response: TokenResponse;
      try {
        response = await flow.complete({
          callbackParams: { ...callback.params },
          state: resume.state,
          codeVerifier: resume.codeVerifier,
          clientId,
          redirectUri: resume.callbackUrl || callbackUrl,
          ...secretFor(clientId),
        });
      } catch (cause) {
        throw new AuthorizationFailedError(connectionName, {
          message:
            cause instanceof Error ? cause.message : "Authorization failed",
          reason:
            cause instanceof AuthorizationDeniedError
              ? FailureReason.ACCESS_DENIED
              : cause instanceof StateMismatchError
                ? FailureReason.INVALID_CALLBACK
                : FailureReason.ACQUISITION_FAILED,
          retryable: false,
        });
      }

      const grant = grantFromResponse(response, {
        id: crypto.randomUUID(),
        clientId,
        resources: resume.resources.length > 0 ? resume.resources : resources,
        scopes,
      });
      await tokens.put(storeKey(principal), grant);
      return toTokenResult(grant);
    },
    /**
     * eve calls this after a rejected bearer. Every grant covering this
     * connection's resource goes, so the next `getToken` parks for a fresh one;
     * grants for other resources stay.
     */
    async evict({ principal }) {
      const key = storeKey(principal);
      const held = await tokens.list(key);
      await Promise.all(
        held
          .filter((grant) => grant.resources.includes(options.resource))
          .map((grant) => tokens.remove(key, grant.id)),
      );
    },
  };
}

/** A process-local store that drops grants once they can no longer mint a token. */
export function memoryAuthorizedTokenStore(): GrantStore {
  const grants = new Map<string, Map<string, AuthorizedGrant>>();
  return {
    async list(principal) {
      const held = grants.get(principal);
      if (!held) return [];
      const now = Date.now();
      for (const [id, grant] of held) {
        if (dead(grant, now)) held.delete(id);
      }
      return [...held.values()];
    },
    async put(principal, grant) {
      let held = grants.get(principal);
      if (!held) {
        held = new Map();
        grants.set(principal, held);
      }
      held.set(grant.id, grant);
    },
    async remove(principal, grantId) {
      grants.get(principal)?.delete(grantId);
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
      return beginAuthorization(issuer, {
        ...beginOptions,
        metadata: await discover(),
      });
    },
    async complete(completeOptions) {
      return completeAuthorization(issuer, {
        ...completeOptions,
        metadata: await discover(),
      });
    },
    async refresh(refreshOptions) {
      return refreshAuthorization(issuer, {
        ...refreshOptions,
        metadata: await discover(),
      });
    },
    /**
     * One public, PKCE-bound client per authorization, holding the single
     * redirect URI that attempt will come back to. `token_endpoint_auth_method:
     * "none"` keeps the resume state free of credentials, and `refresh_token`
     * is requested so a long-lived grant can be renewed without sending the
     * user back through the browser.
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

/**
 * The grant a token response settles. The server's `scope` is authoritative
 * when present; otherwise the scopes are the ones requested (RFC 6749 section
 * 5.1 lets the server omit `scope` when it granted exactly those).
 */
function grantFromResponse(
  response: TokenResponse,
  issued: {
    id: string;
    clientId: string;
    resources: readonly string[];
    scopes: readonly string[];
    refreshToken?: string;
  },
): AuthorizedGrant {
  const expiry = expiresAt(response.expiresIn);
  const refreshToken = response.refreshToken ?? issued.refreshToken;
  return {
    id: issued.id,
    accessToken: response.accessToken,
    ...(expiry !== undefined ? { expiresAt: expiry } : {}),
    ...(refreshToken !== undefined ? { refreshToken } : {}),
    clientId: issued.clientId,
    resources: [...issued.resources],
    scopes: response.scope ? splitScopes(response.scope) : [...issued.scopes],
  };
}

function expired(grant: AuthorizedGrant, now: number): boolean {
  return grant.expiresAt !== undefined && grant.expiresAt <= now;
}

/** Expired with no refresh token: nothing can mint a new access token. */
function dead(grant: AuthorizedGrant, now: number): boolean {
  return expired(grant, now) && !grant.refreshToken;
}

function nearExpiry(grant: AuthorizedGrant, now: number): boolean {
  return (
    grant.expiresAt !== undefined && grant.expiresAt - REFRESH_SKEW_MS <= now
  );
}

function storeKey(principal: ConnectionPrincipal): string {
  if (principal.type !== "user") return "app";
  return principalKey(principal);
}

function toTokenResult(grant: AuthorizedGrant): TokenResult {
  return {
    token: grant.accessToken,
    ...(grant.expiresAt !== undefined ? { expiresAt: grant.expiresAt } : {}),
  };
}

function requireUser(
  principal: ConnectionPrincipal,
  connectionName: string,
): void {
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
  return Array.isArray(scopes)
    ? [...scopes]
    : (scopes as string).split(" ").filter(Boolean);
}
