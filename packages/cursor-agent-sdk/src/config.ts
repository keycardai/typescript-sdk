import type { SecretRef } from "@grok/agent-sdk";
import {
  AuthProviderConfigurationError,
  ClientSecret,
  type ApplicationCredential,
  type ClientCredentialsRequest,
} from "@keycardai/oauth";
import { WorkloadIdentity } from "@keycardai/oauth/server";

import {
  CursorDeploymentTokenSource,
  type CursorOidcTokenFetcher,
} from "./cursorOidc.js";
import { ConnectionAuthError, FailureReason } from "./errors.js";
import {
  defaultSubjectTokenStore,
  type HostKvSubjectTokenStore,
  type SubjectTokenStore,
} from "./subjectTokens.js";
import { KeycardZoneClient, type ZoneClient } from "./zoneClient.js";

/** Default skew: a cached token this close to expiry is replaced. */
export const DEFAULT_EXPIRY_SKEW_SECONDS = 60;

/** Options for authenticating a Cursor-hosted deployment with a Cursor OIDC token. */
export interface CursorWorkloadIdentityOptions {
  /** Public ID of the v2 token credential in the Keycard zone. */
  clientId: string;
  /**
   * Audience requested from Cursor's `getOidcToken`. Defaults to the zone
   * issuer URL. Must match the token credential's allowed audience and be
   * declared in `hosting.oidc.audiences`.
   */
  audience?: string;
  /**
   * Optional override for Cursor's `getOidcToken` helper, primarily for tests.
   * When omitted, `@grok/agent-sdk` is resolved lazily on the first token request.
   */
  getOidcToken?: CursorOidcTokenFetcher;
  /** @internal Override for loading `@grok/agent-sdk`, used in tests. */
  loadSdk?: () => Promise<{ getOidcToken?: unknown }>;
}

/** Options shared by every Keycard connection auth factory. */
export interface KeycardConnectionOptions {
  /** The resource URL tokens are minted for. Configuration, never a model argument. */
  resource: string;
  /** Keycard zone URL (issuer). Required unless `client` is given. */
  zoneUrl?: string;
  /**
   * How the agent authenticates to the zone: `ClientSecret` for Keycard-issued
   * client credentials, or any other `ApplicationCredential`. Mutually
   * exclusive with `clientId` / `clientSecret` and `cursorWorkloadIdentity`.
   */
  applicationCredential?: ApplicationCredential;
  /** With `clientSecret`, shorthand for `applicationCredential: new ClientSecret(clientId, clientSecret)`. */
  clientId?: string;
  /**
   * The secret, or the SDK's `{ secretName }` reference to it. A `SecretRef`
   * is resolved when the provider runs, from `process.env[secretName]`, never
   * when the connection module is imported: on Cursor hosting the platform
   * binds a deployment's secrets per request, long after discovery imported
   * the module.
   */
  clientSecret?: string | SecretRef;
  /**
   * Explicitly selects the hosted Cursor deployment OIDC credential path
   * (requires `@grok/agent-sdk` 0.7.1 or later). Mutually exclusive with
   * `applicationCredential` and `clientId` / `clientSecret`.
   */
  cursorWorkloadIdentity?: CursorWorkloadIdentityOptions;
  /** Scopes requested from the zone for this connection. */
  requestScopes?: string | readonly string[];
  /** The header the minted token is returned under, as `Bearer <token>`. Defaults to `authorization`. */
  headerName?: string;
  /** Seconds before expiry at which a cached token is replaced. Defaults to 60. */
  expirySkewSeconds?: number;
  /** Pre-built zone client. Replaces `zoneUrl`, and takes no network in tests. */
  client?: ZoneClient;
  /** Name used in error messages only. Never a cache key. */
  connectionName?: string;
  /**
   * Where `onBehalfOf` reads the retained subject token from. Pass the host KV
   * store from `hostKvSubjectTokenStore()` for `"host-kv"` mode; defaults to
   * the shared process-local store otherwise.
   */
  subjectTokens?: SubjectTokenStore | HostKvSubjectTokenStore;
}

/** One factory's resolved configuration, validated once at definition time. */
export interface ResolvedConnectionConfig {
  readonly resource: string;
  readonly scope?: string;
  readonly connectionName: string;
  readonly headerName: string;
  readonly skewMs: number;
  /** The configured zone issuer, without a trailing slash; undefined with an injected client. */
  readonly issuer?: string;
  readonly subjectTokens: SubjectTokenStore | HostKvSubjectTokenStore;
  /** The credential for this call, resolving a `SecretRef` now. Undefined when none is configured. */
  credential(): ApplicationCredential | undefined;
  /** The warm zone client, built on first use and rebuilt only when a `SecretRef` value changes. */
  zoneClient(): ZoneClient;
  /** Client-authentication fields an assertion credential adds to a request body. */
  clientAuthFields(): Promise<Partial<ClientCredentialsRequest>>;
}

function isSecretRef(value: unknown): value is SecretRef {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as SecretRef).secretName === "string"
  );
}

/**
 * Validates and resolves factory options.
 *
 * Configuration mistakes throw here, when the connection module is loaded,
 * rather than on the first turn. A `SecretRef` is the exception by design:
 * its value is read per call, so an unset secret is a call-time
 * `credential_unavailable`, not an import-time failure.
 */
export function resolveConnectionConfig(
  options: KeycardConnectionOptions,
  factory: string,
): ResolvedConnectionConfig {
  if (!options.resource || !options.resource.trim()) {
    throw new AuthProviderConfigurationError(`${factory} requires a resource URL`);
  }
  if (!options.zoneUrl && !options.client) {
    throw new AuthProviderConfigurationError(`${factory} requires zoneUrl or client`);
  }
  const hasSecretShorthand = options.clientId !== undefined || options.clientSecret !== undefined;
  if (options.cursorWorkloadIdentity !== undefined) {
    if (options.applicationCredential || hasSecretShorthand) {
      throw new AuthProviderConfigurationError(
        `${factory} accepts only one credential: cursorWorkloadIdentity cannot be combined with applicationCredential or clientId/clientSecret`,
      );
    }
    if (
      typeof options.cursorWorkloadIdentity.clientId !== "string" ||
      !options.cursorWorkloadIdentity.clientId.trim()
    ) {
      throw new AuthProviderConfigurationError(
        `${factory} cursorWorkloadIdentity requires a non-empty clientId`,
      );
    }
    if (
      options.cursorWorkloadIdentity.audience !== undefined &&
      (typeof options.cursorWorkloadIdentity.audience !== "string" ||
        !options.cursorWorkloadIdentity.audience.trim())
    ) {
      throw new AuthProviderConfigurationError(
        `${factory} cursorWorkloadIdentity audience must not be blank`,
      );
    }
  }
  if (options.applicationCredential && (options.clientId || options.clientSecret)) {
    throw new AuthProviderConfigurationError(
      `${factory} accepts either applicationCredential or clientId/clientSecret, not both`,
    );
  }
  if (Boolean(options.clientId) !== Boolean(options.clientSecret)) {
    throw new AuthProviderConfigurationError(
      `${factory} requires both clientId and clientSecret when using the shorthand`,
    );
  }
  if (isSecretRef(options.clientSecret) && !options.clientSecret.secretName.trim()) {
    throw new AuthProviderConfigurationError(`${factory} requires a non-empty secretName`);
  }

  const connectionName = options.connectionName ?? options.resource;
  const issuer = options.zoneUrl?.replace(/\/+$/, "");
  const scope = joinScopes(options.requestScopes);
  const skewSeconds = options.expirySkewSeconds ?? DEFAULT_EXPIRY_SKEW_SECONDS;

  let cursorCredential: WorkloadIdentity | undefined;
  if (options.cursorWorkloadIdentity !== undefined) {
    const audience = options.cursorWorkloadIdentity.audience ?? issuer;
    if (!audience || !audience.trim()) {
      throw new AuthProviderConfigurationError(
        `${factory} cursorWorkloadIdentity requires zoneUrl or an explicit audience`,
      );
    }
    const source = new CursorDeploymentTokenSource({
      audience,
      ...(options.cursorWorkloadIdentity.getOidcToken
        ? { getOidcToken: options.cursorWorkloadIdentity.getOidcToken }
        : {}),
      ...(options.cursorWorkloadIdentity.loadSdk
        ? { loadSdk: options.cursorWorkloadIdentity.loadSdk }
        : {}),
    });
    cursorCredential = new WorkloadIdentity(source, {
      clientId: options.cursorWorkloadIdentity.clientId,
    });
  }

  const resolveCredential = (): ApplicationCredential | undefined => {
    if (cursorCredential) return cursorCredential;
    if (options.applicationCredential) return options.applicationCredential;
    if (!options.clientId) return undefined;
    if (isSecretRef(options.clientSecret)) {
      const value = process.env[options.clientSecret.secretName];
      if (!value) {
        throw new ConnectionAuthError(
          FailureReason.CREDENTIAL_UNAVAILABLE,
          connectionName,
          `the deployment secret ${options.clientSecret.secretName} is not set`,
        );
      }
      return new ClientSecret(options.clientId, value);
    }
    return new ClientSecret(options.clientId, options.clientSecret as string);
  };

  let client = options.client;
  let clientSecretValue: string | undefined;

  return {
    resource: options.resource,
    ...(scope ? { scope } : {}),
    connectionName,
    headerName: options.headerName ?? "authorization",
    skewMs: skewSeconds * 1000,
    ...(issuer ? { issuer } : {}),
    subjectTokens: options.subjectTokens ?? defaultSubjectTokenStore,
    credential: resolveCredential,
    zoneClient() {
      if (options.client) return options.client;
      const credential = resolveCredential();
      const secret = credential instanceof ClientSecret ? credential.getAuth()?.clientSecret : undefined;
      if (!client || secret !== clientSecretValue) {
        clientSecretValue = secret;
        client = new KeycardZoneClient(issuer!, credential);
      }
      return client;
    },
    /**
     * Assertion-based credentials carry no HTTP-level auth; their proof rides
     * in the request body as a jwt-bearer client assertion. The credential
     * protocol only exposes request preparation for token exchange, so this
     * prepares one and lifts the client-auth fields for the
     * client-credentials call. `ClientSecret` authenticates at the HTTP layer
     * and contributes nothing here.
     */
    async clientAuthFields(): Promise<Partial<ClientCredentialsRequest>> {
      const credential = resolveCredential();
      if (!credential) return {};
      const prepared = await credential.prepareTokenExchangeRequest(
        "client-credentials",
        options.resource,
      );
      if (!prepared.clientAssertion) return {};
      const fields: Partial<ClientCredentialsRequest> = {
        clientAssertion: prepared.clientAssertion,
        clientAssertionType: prepared.clientAssertionType,
      };
      if (prepared.clientId) fields.clientId = prepared.clientId;
      return fields;
    },
  };
}

function joinScopes(scopes: string | readonly string[] | undefined): string | undefined {
  if (scopes === undefined) return undefined;
  const value = Array.isArray(scopes) ? scopes.join(" ") : (scopes as string);
  return value || undefined;
}
