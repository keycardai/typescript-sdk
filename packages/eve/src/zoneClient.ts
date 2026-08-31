import {
  ClientCredentialsClient,
  TokenExchangeClient,
  type ApplicationCredential,
  type ClientCredentialsRequest,
  type ImpersonateRequest,
  type TokenExchangeRequest,
  type TokenResponse,
} from "@keycardai/oauth";

/**
 * The zone operations a connection auth factory needs, as one seam.
 *
 * `@keycardai/oauth` splits acquisition across `TokenExchangeClient` and
 * `ClientCredentialsClient`; this interface is the single injection point the
 * contract calls for (`client`), and lets a test stand in for the zone with no
 * network.
 */
export interface ZoneClient {
  /** RFC 8693 exchange of a subject token for a resource token. */
  exchangeToken(
    request: TokenExchangeRequest,
    options?: { issuer?: string },
  ): Promise<TokenResponse>;
  /** Substitute-user exchange for a user the agent holds no token for. */
  impersonate(request: ImpersonateRequest): Promise<TokenResponse>;
  /** Client-credentials grant under the agent's own authority. */
  clientCredentialsGrant(
    request?: ClientCredentialsRequest,
    options?: { issuer?: string },
  ): Promise<TokenResponse>;
}

/**
 * The default `ZoneClient`: one warm `TokenExchangeClient` and one warm
 * `ClientCredentialsClient` per factory.
 *
 * Both underlying clients cache authorization-server metadata after their
 * first call, so discovery happens once per process rather than once per tool
 * call. eve resolves connection auth on every step, which makes per-call
 * client construction the thing to avoid here.
 */
export class KeycardZoneClient implements ZoneClient {
  #issuer: string;
  #exchange: TokenExchangeClient;
  #clientCredentials: ClientCredentialsClient;

  constructor(issuer: string, credential?: ApplicationCredential) {
    this.#issuer = issuer;
    this.#exchange = new TokenExchangeClient(issuer, { credential });
    this.#clientCredentials = new ClientCredentialsClient(issuer, { credential });
  }

  exchangeToken(
    request: TokenExchangeRequest,
    options?: { issuer?: string },
  ): Promise<TokenResponse> {
    return this.#exchange.exchangeToken(request, { issuer: options?.issuer ?? this.#issuer });
  }

  impersonate(request: ImpersonateRequest): Promise<TokenResponse> {
    return this.#exchange.impersonate(request);
  }

  clientCredentialsGrant(
    request?: ClientCredentialsRequest,
    options?: { issuer?: string },
  ): Promise<TokenResponse> {
    return this.#clientCredentials.requestToken(request, {
      issuer: options?.issuer ?? this.#issuer,
    });
  }
}
