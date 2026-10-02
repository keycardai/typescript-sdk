import {
  AuthProviderConfigurationError,
  ClientSecret,
  type ApplicationCredential,
  type ClientCredentialsRequest,
} from "@keycardai/oauth";

import { defaultApplicationCredential } from "./vercel.js";
import { KeycardZoneClient, type ZoneClient } from "./zoneClient.js";
import { defaultSubjectTokenStore, type SubjectTokenStore } from "./subjectTokens.js";

/** Options shared by every Keycard connection auth factory. */
export interface KeycardConnectionOptions {
  /** The resource URL tokens are minted for. */
  resource: string;
  /**
   * Keycard zone URL (issuer). Defaults to `KEYCARD_ZONE_URL`; one of the two
   * is required unless `client` is given.
   */
  zoneUrl?: string;
  /**
   * How the agent authenticates to the zone. Defaults to
   * {@link vercelWorkloadIdentity}, the deployment's Vercel OIDC token, so an
   * agent on Vercel holds no secret. Pass `ClientSecret` for Keycard-issued
   * client credentials, or any other `ApplicationCredential` on another host.
   * Mutually exclusive with `clientId` / `clientSecret`.
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
  /**
   * An environment variable holding a token already brokered for this
   * resource, as `keycard run` hydrates one from `keycard.toml`. When it is
   * set and non-empty, `asSelf` and `impersonate` return it without contacting
   * the zone, so a local run needs no workload identity. Leave the variable
   * unset in deployed environments: whatever it holds is served to every
   * principal of the connection.
   */
  localTokenEnv?: string;
  /**
   * What a `user_authorization_required` failure tells the user to do, in
   * place of the default `keycard auth resource` command. Use it when the
   * grant spans more than this connection's resource, such as an MCP server
   * that exchanges the token for an upstream provider's.
   */
  authorizationHint?: string;
}

/** One factory's resolved configuration, validated once at definition time. */
export interface ResolvedConnectionConfig {
  readonly resource: string;
  readonly scope?: string;
  readonly connectionName: string;
  readonly credential?: ApplicationCredential;
  readonly subjectTokens: SubjectTokenStore;
  /** The instruction a `user_authorization_required` failure ends with. */
  readonly authorizationHint: string;
  /** The `localTokenEnv` token, when one is set for this process. */
  localToken(): string | undefined;
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
  const zoneUrl = zoneUrlOption(options.zoneUrl);
  if (!zoneUrl && !options.client) {
    throw new AuthProviderConfigurationError(
      `${factory} requires zoneUrl or the KEYCARD_ZONE_URL environment variable`,
    );
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

  // An injected client authenticates itself, so it gets no default.
  let credential: ApplicationCredential | undefined;
  if (options.applicationCredential) {
    credential = options.applicationCredential;
  } else if (options.clientId && options.clientSecret) {
    credential = new ClientSecret(options.clientId, options.clientSecret);
  } else if (!options.client) {
    credential = defaultApplicationCredential();
  }

  let client = options.client;
  const scope = joinScopes(options.requestScopes);

  return {
    resource: options.resource,
    ...(scope ? { scope } : {}),
    connectionName: options.connectionName ?? options.resource,
    ...(credential ? { credential } : {}),
    subjectTokens: options.subjectTokens ?? defaultSubjectTokenStore,
    authorizationHint:
      options.authorizationHint ??
      `Run \`keycard auth resource ${options.resource}${zoneFlag(zoneUrl)}\`, then retry.`,
    localToken() {
      const token = options.localTokenEnv ? process.env[options.localTokenEnv]?.trim() : undefined;
      return token || undefined;
    },
    zoneClient() {
      if (!client) client = new KeycardZoneClient(zoneUrl!, credential);
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

/** The zone URL an option names, falling back to `KEYCARD_ZONE_URL`. */
export function zoneUrlOption(zoneUrl: string | undefined): string | undefined {
  return zoneUrl || process.env.KEYCARD_ZONE_URL?.trim() || undefined;
}

/** ` --zone <id>` for a `<id>.keycard.cloud` zone URL, otherwise nothing. */
function zoneFlag(zoneUrl: string | undefined): string {
  if (!zoneUrl) return "";
  try {
    const host = new URL(zoneUrl).host;
    return host.endsWith(".keycard.cloud") ? ` --zone ${host.split(".")[0]}` : "";
  } catch {
    return "";
  }
}

function joinScopes(scopes: string | readonly string[] | undefined): string | undefined {
  if (scopes === undefined) return undefined;
  const value = Array.isArray(scopes) ? scopes.join(" ") : (scopes as string);
  return value || undefined;
}
