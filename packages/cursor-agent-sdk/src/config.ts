import type { SecretRef } from "@grok/agent-sdk";
import {
  AuthProviderConfigurationError,
  ClientSecret,
  type ApplicationCredential,
  type ClientCredentialsRequest,
} from "@keycardai/oauth";

import { ConnectionAuthError, FailureReason } from "./errors.js";
import { defaultSubjectTokenStore, type SubjectTokenStore } from "./subjectTokens.js";
import { KeycardZoneClient, type ZoneClient } from "./zoneClient.js";

/** Default skew: a cached token this close to expiry is replaced. */
export const DEFAULT_EXPIRY_SKEW_SECONDS = 60;

/** Options shared by every Keycard connection auth factory. */
export interface KeycardConnectionOptions {
  /** The resource URL tokens are minted for. Configuration, never a model argument. */
  resource: string;
  /** Keycard zone URL (issuer). Required unless `client` is given. */
  zoneUrl?: string;
  /**
   * How the agent authenticates to the zone: `ClientSecret` for Keycard-issued
   * client credentials, or any other `ApplicationCredential`. Mutually
   * exclusive with `clientId` / `clientSecret`.
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
  /** Where `onBehalfOf` reads the retained subject token from. Defaults to the shared store. */
  subjectTokens?: SubjectTokenStore;
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
  readonly subjectTokens: SubjectTokenStore;
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

  const resolveCredential = (): ApplicationCredential | undefined => {
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
