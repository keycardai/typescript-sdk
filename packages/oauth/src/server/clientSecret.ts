import type { ApplicationCredential } from "../credentials.js";
import type { TokenExchangeRequest } from "../tokenExchange.js";

const ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
const DEFAULT_ZONE = "__default__";

export type ClientSecretCredentials =
  | [clientId: string, clientSecret: string]
  | Record<string, [clientId: string, clientSecret: string]>;

export class ClientSecret implements ApplicationCredential {
  #zoneCredentials: Map<string, [string, string]>;
  #isMultiZone: boolean;

  constructor(clientId: string, clientSecret: string);
  constructor(credentials: ClientSecretCredentials);
  constructor(
    arg1: string | ClientSecretCredentials,
    arg2?: string,
  ) {
    this.#zoneCredentials = new Map();

    if (typeof arg1 === "string") {
      if (typeof arg2 !== "string") {
        throw new TypeError("ClientSecret: client_secret is required when client_id is provided as a string");
      }
      this.#zoneCredentials.set(DEFAULT_ZONE, [arg1, arg2]);
      this.#isMultiZone = false;
      return;
    }

    if (Array.isArray(arg1)) {
      const [clientId, clientSecret] = arg1;
      if (typeof clientId !== "string" || typeof clientSecret !== "string") {
        throw new TypeError("ClientSecret: tuple must be [clientId, clientSecret]");
      }
      this.#zoneCredentials.set(DEFAULT_ZONE, [clientId, clientSecret]);
      this.#isMultiZone = false;
      return;
    }

    if (arg1 && typeof arg1 === "object") {
      for (const [zoneId, tuple] of Object.entries(arg1)) {
        if (!Array.isArray(tuple) || typeof tuple[0] !== "string" || typeof tuple[1] !== "string") {
          throw new TypeError(`ClientSecret: zone "${zoneId}" must map to [clientId, clientSecret]`);
        }
        this.#zoneCredentials.set(zoneId, [tuple[0], tuple[1]]);
      }
      if (this.#zoneCredentials.size === 0) {
        throw new TypeError("ClientSecret: zone-keyed credentials must contain at least one zone");
      }
      this.#isMultiZone = true;
      return;
    }

    throw new TypeError("ClientSecret: unsupported credentials shape");
  }

  getAuth(zoneId?: string): { clientId: string; clientSecret: string } | null {
    if (!this.#isMultiZone) {
      const tuple = this.#zoneCredentials.get(DEFAULT_ZONE);
      return tuple ? { clientId: tuple[0], clientSecret: tuple[1] } : null;
    }
    if (!zoneId) {
      return null;
    }
    const tuple = this.#zoneCredentials.get(zoneId);
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
