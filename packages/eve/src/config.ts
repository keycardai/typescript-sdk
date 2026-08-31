import {
  AuthProviderConfigurationError,
  ClientSecret,
  type ApplicationCredential,
  type ClientCredentialsRequest,
} from "@keycardai/oauth";

import { KeycardZoneClient, type ZoneClient } from "./zoneClient.js";
import { defaultSubjectTokenStore, type SubjectTokenStore } from "./subjectTokens.js";

/** Options shared by every Keycard connection auth factory. */
export interface KeycardConnectionOptions {
  /** The resource URL tokens are minted for. */
  resource: string;
  /** Keycard zone URL (issuer). Required unless `client` is given. */
  zoneUrl?: string;
  /**
   * How the agent authenticates to the zone: `ClientSecret` for Keycard-issued
   * client credentials, or any other `ApplicationCredential`. Mutually
   * exclusive with `clientId` / `clientSecret`.
   */
  applicationCredential?: ApplicationCredential;
  /** Shorthand for `applicationCredential: new ClientSecret(clientId, clientSecret)`. */
  clientId?: string;
  /** Shorthand for `applicationCredential: new ClientSecret(clientId, clientSecret)`. */
  clientSecret?: string;
  /** Scopes requested from the zone for this connection. */
  requestScopes?: string | readonly string[];
  /** Pre-built zone client. Replaces `zoneUrl`, and takes no network in tests. */
  client?: ZoneClient;
  /** Name used in error messages and eve's authorization events. */
  connectionName?: string;
  /** Where the verified inbound bearer is read from. Defaults to the shared store. */
  subjectTokens?: SubjectTokenStore;
}

/** One factory's resolved configuration, validated once at definition time. */
export interface ResolvedConnectionConfig {
  readonly resource: string;
  readonly scope?: string;
  readonly connectionName: string;
  readonly credential?: ApplicationCredential;
  readonly subjectTokens: SubjectTokenStore;
  /** The warm zone client, built on first use and reused after that. */
  zoneClient(): ZoneClient;
  /** Client-authentication fields an assertion credential adds to a request body. */
  clientAuthFields(): Promise<Partial<ClientCredentialsRequest>>;
}

/**
 * Validates and resolves factory options.
 *
 * Configuration mistakes throw here, when the connection module is loaded,
 * rather than on the first tool call inside a turn.
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

  let credential: ApplicationCredential | undefined;
  if (options.applicationCredential) {
    credential = options.applicationCredential;
  } else if (options.clientId && options.clientSecret) {
    credential = new ClientSecret(options.clientId, options.clientSecret);
  }

  let client = options.client;
  const scope = joinScopes(options.requestScopes);

  return {
    resource: options.resource,
    ...(scope ? { scope } : {}),
    connectionName: options.connectionName ?? options.resource,
    ...(credential ? { credential } : {}),
    subjectTokens: options.subjectTokens ?? defaultSubjectTokenStore,
    zoneClient() {
      if (!client) client = new KeycardZoneClient(options.zoneUrl!, credential);
      return client;
    },
    /**
     * Assertion-based credentials carry no HTTP-level auth; their proof rides
     * in the request body as a jwt-bearer client assertion. The credential
     * protocol only exposes request preparation for token exchange, so this
     * prepares one and lifts the client-auth fields for the
     * client-credentials call. `ClientSecret` authenticates at the HTTP layer
     * and contributes nothing here.
     *
     * The subject token below is a placeholder: client credentials has no
     * subject, and only the client-auth fields of the prepared request are
     * read.
     */
    async clientAuthFields(): Promise<Partial<ClientCredentialsRequest>> {
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

/** Absolute expiry for eve, from the zone's relative `expires_in`. */
export function expiresAt(expiresIn: number | undefined): number | undefined {
  if (typeof expiresIn !== "number" || !Number.isFinite(expiresIn)) return undefined;
  return Date.now() + expiresIn * 1000;
}

function joinScopes(scopes: string | readonly string[] | undefined): string | undefined {
  if (scopes === undefined) return undefined;
  const value = Array.isArray(scopes) ? scopes.join(" ") : (scopes as string);
  return value || undefined;
}
