import { createClientAuthentication, type ApplicationCredential, type ClientAuthentication } from "../credentials.js";
import { basicAuthorization } from "../basicAuthorization.js";
import { ConfigurationError } from "../errors.js";
import { omitWhenPrinted } from "../printed.js";
import { omitTokenExchangeSecrets, type TokenExchangeRequest } from "../tokenExchange.js";

const ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
const SINGLE_CREDENTIAL_KEY = "__default__";

function requireNonEmptyCredential(
  clientId: string,
  clientSecret: string,
  issuerContext = "",
): void {
  if (clientId.length === 0 || clientSecret.length === 0) {
    throw new TypeError(
      `ClientSecret: client_id and client_secret must be non-empty strings${issuerContext}`,
    );
  }
}

/**
 * Strips trailing slashes so "https://zone.keycard.cloud/" and
 * "https://zone.keycard.cloud" select the same credential entry.
 */
function normalizeIssuer(issuer: string): string {
  return issuer.replace(/\/+$/, "");
}

export type ClientSecretCredentials =
  | [clientId: string, clientSecret: string]
  | Record<string, [clientId: string, clientSecret: string]>;

export class ClientSecret implements ApplicationCredential {
  #credentialsByIssuer: Map<string, [string, string]>;
  #isMultiZone: boolean;

  constructor(clientId: string, clientSecret: string);
  constructor(credentials: ClientSecretCredentials);
  constructor(
    arg1: string | ClientSecretCredentials,
    arg2?: string,
  ) {
    this.#credentialsByIssuer = new Map();

    if (typeof arg1 === "string") {
      if (typeof arg2 !== "string") {
        throw new TypeError("ClientSecret: client_secret is required when client_id is provided as a string");
      }
      requireNonEmptyCredential(arg1, arg2);
      this.#credentialsByIssuer.set(SINGLE_CREDENTIAL_KEY, [arg1, arg2]);
      this.#isMultiZone = false;
      return;
    }

    if (Array.isArray(arg1)) {
      const [clientId, clientSecret] = arg1;
      if (typeof clientId !== "string" || typeof clientSecret !== "string") {
        throw new TypeError("ClientSecret: tuple must be [clientId, clientSecret]");
      }
      requireNonEmptyCredential(clientId, clientSecret);
      this.#credentialsByIssuer.set(SINGLE_CREDENTIAL_KEY, [clientId, clientSecret]);
      this.#isMultiZone = false;
      return;
    }

    if (arg1 && typeof arg1 === "object") {
      // Multi-zone shape: keys are zone issuer URLs, e.g.
      // "https://zone-a.keycard.cloud" -> ["client-id", "client-secret"].
      for (const [issuer, tuple] of Object.entries(arg1)) {
        if (!Array.isArray(tuple) || typeof tuple[0] !== "string" || typeof tuple[1] !== "string") {
          throw new TypeError(`ClientSecret: issuer "${issuer}" must map to [clientId, clientSecret]`);
        }
        requireNonEmptyCredential(tuple[0], tuple[1], ` for issuer "${issuer}"`);
        this.#credentialsByIssuer.set(normalizeIssuer(issuer), [tuple[0], tuple[1]]);
      }
      if (this.#credentialsByIssuer.size === 0) {
        throw new TypeError("ClientSecret: issuer-keyed credentials must contain at least one issuer");
      }
      this.#isMultiZone = true;
      return;
    }

    throw new TypeError("ClientSecret: unsupported credentials shape");
  }

  /**
   * The zone issuers a multi-zone credential is configured with, without a
   * trailing slash. `undefined` for a single-zone credential.
   * `authenticateFromChallenge` uses them as its allow-list when
   * `allowedIssuers` is unset.
   */
  get zoneIssuers(): readonly string[] | undefined {
    return this.#isMultiZone ? [...this.#credentialsByIssuer.keys()] : undefined;
  }

  getAuth(issuer?: string): { clientId: string; clientSecret: string } | null {
    if (!this.#isMultiZone) {
      const tuple = this.#credentialsByIssuer.get(SINGLE_CREDENTIAL_KEY);
      return tuple ? printedAuth(tuple) : null;
    }
    if (!issuer) {
      return null;
    }
    const tuple = this.#credentialsByIssuer.get(normalizeIssuer(issuer));
    return tuple ? printedAuth(tuple) : null;
  }

  /**
   * Returns an HTTP Basic `Authorization` header for the zone `issuer`. `form`
   * is empty. A multi-zone credential throws `ConfigurationError` for an
   * issuer it has no credentials for.
   */
  async clientAuthentication(issuer: string, _endpoint: string): Promise<ClientAuthentication> {
    const auth = this.getAuth(issuer);
    if (!auth) {
      throw new ConfigurationError(`ClientSecret: no client credentials configured for issuer "${issuer}"`);
    }
    return createClientAuthentication({ Authorization: basicAuthorization(auth.clientId, auth.clientSecret) }, {});
  }

  async prepareTokenExchangeRequest(
    subjectToken: string,
    resource: string,
  ): Promise<TokenExchangeRequest> {
    return omitTokenExchangeSecrets({
      subjectToken,
      resource,
      subjectTokenType: ACCESS_TOKEN_TYPE,
    });
  }
}

/** `{ clientId, clientSecret }` that `util.inspect` prints without `clientSecret`. */
function printedAuth([clientId, clientSecret]: [string, string]): { clientId: string; clientSecret: string } {
  return omitWhenPrinted({ clientId, clientSecret }, "ClientAuth", ["clientSecret"]);
}
