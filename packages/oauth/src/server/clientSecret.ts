import type { ApplicationCredential } from "../credentials.js";
import type { TokenExchangeRequest } from "../tokenExchange.js";

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

  getAuth(issuer?: string): { clientId: string; clientSecret: string } | null {
    if (!this.#isMultiZone) {
      const tuple = this.#credentialsByIssuer.get(SINGLE_CREDENTIAL_KEY);
      return tuple ? { clientId: tuple[0], clientSecret: tuple[1] } : null;
    }
    if (!issuer) {
      return null;
    }
    const tuple = this.#credentialsByIssuer.get(normalizeIssuer(issuer));
    return tuple ? { clientId: tuple[0], clientSecret: tuple[1] } : null;
  }

  async prepareTokenExchangeRequest(
    subjectToken: string,
    resource: string,
  ): Promise<TokenExchangeRequest> {
    return {
      subjectToken,
      resource,
      subjectTokenType: ACCESS_TOKEN_TYPE,
    };
  }
}
