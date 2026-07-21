import type {
  AuthorizationServerMetadata,
  OAuthClientInformationContext,
  OAuthClientMetadata,
  OAuthClientProvider,
  OAuthDiscoveryState,
  StoredOAuthClientInformation,
  StoredOAuthTokens,
} from '@modelcontextprotocol/client';
import type { PrivateKeyring } from "@keycardai/oauth/keyring";
import { JSONWebTokenSigner } from "../signers/jwt.js";

export interface OAuthTokensStore {
  get(ctx?: OAuthClientInformationContext): Promise<StoredOAuthTokens | undefined>;
  save(tokens: StoredOAuthTokens, ctx?: OAuthClientInformationContext): void | Promise<void>;
}

export interface OAuthCodeVerifierStore {
  get(): string | Promise<string>;
  save(codeVerifier: string): void | Promise<void>;
}

/**
 * Persists OAuth discovery state (SEP-2352) so the MCP SDK can skip
 * redundant RFC 9728 / RFC 8414 discovery requests and verify that the
 * authorization server on the redirect callback leg matches the one
 * recorded before the redirect.
 *
 * Implementations MUST persist with the same durability as the code
 * verifier store: the state has to survive the authorization redirect
 * round-trip.
 */
export interface OAuthDiscoveryStateStore {
  get(): OAuthDiscoveryState | undefined | Promise<OAuthDiscoveryState | undefined>;
  save(state: OAuthDiscoveryState): void | Promise<void>;
}

export interface BaseOAuthClientProviderOptions {
  redirectUrl?: string | URL;
  tokensStore?: OAuthTokensStore;
  codeVerifierStore?: OAuthCodeVerifierStore;
  discoveryStateStore?: OAuthDiscoveryStateStore;
  privateKeyring?: PrivateKeyring;
}

export class BaseOAuthClientProvider implements OAuthClientProvider {
  private _redirectUrl: string | URL | undefined;


  private _clientId: string | undefined;
  private _metadata: OAuthClientMetadata;
  protected privateKeyring: PrivateKeyring | undefined;
  protected tokensStore: OAuthTokensStore | undefined;
  protected codeVerifierStore: OAuthCodeVerifierStore | undefined;
  protected discoveryStateStore: OAuthDiscoveryStateStore | undefined;

  /**
   * SEP-2352 discovery-state persistence. Defined only when a
   * `discoveryStateStore` is configured: the MCP SDK treats the presence of
   * `saveDiscoveryState` as a promise that discovery state is durably
   * persisted, and fails the authorization callback leg when the method
   * exists but no recorded state can be read back. A provider without a
   * store must therefore not define these members at all.
   */
  saveDiscoveryState?: (state: OAuthDiscoveryState) => void | Promise<void>;
  discoveryState?: () => OAuthDiscoveryState | undefined | Promise<OAuthDiscoveryState | undefined>;

  constructor(metadata: OAuthClientMetadata, clientId?: string, options?: BaseOAuthClientProviderOptions) {
    this._clientId = clientId;
    this._metadata = metadata;
    this._redirectUrl = options?.redirectUrl;
    this.tokensStore = options?.tokensStore;
    this.codeVerifierStore = options?.codeVerifierStore;
    this.privateKeyring = options?.privateKeyring;

    const discoveryStateStore = options?.discoveryStateStore;
    if (discoveryStateStore) {
      this.discoveryStateStore = discoveryStateStore;
      this.saveDiscoveryState = (state) => discoveryStateStore.save(state);
      this.discoveryState = () => discoveryStateStore.get();
    }

    // workaround to bind function to this context, since underlying
    // MCP library calls it without a context.
    this.addClientAuthentication = this.addClientAuthentication.bind(this);
  }

  async addClientAuthentication(
    headers: Headers,
    params: URLSearchParams,
    url: string | URL,
    metadata?: AuthorizationServerMetadata,
  ): Promise<void> {
    const clientInfo = await this.clientInformation();
    if (!clientInfo) {
      throw new Error("Client information not available for authentication");
    }
    const clientInformation = { ...this._metadata, ...clientInfo };
    const authMethod = clientInformation.token_endpoint_auth_method || 'client_secret_basic';

    switch (authMethod) {
      case 'private_key_jwt': {
        if (!this.privateKeyring) {
          throw new Error("Private keyring not initialized");
        }

        // The MCP SDK passes the token endpoint URL being called as `url`;
        // prefer the metadata value when present since it is the validated
        // RFC 8414 document entry.
        const tokenUrl = metadata?.token_endpoint
          ? new URL(metadata.token_endpoint)
          : new URL(url);
        const now = Date.now();
        const signer = new JSONWebTokenSigner(this.privateKeyring);
        // RFC 7523 section 3: for client authentication both "iss" and
        // "sub" MUST be the client_id, and "aud" identifies the token
        // endpoint.
        const token = await signer.signToken({
          issuer: clientInformation.client_id,
          userId: clientInformation.client_id,
          resource: tokenUrl,
          issuedAt: Math.floor(now / 1000),
          // 300s tolerates client clocks lagging the AS; the jti below keeps
          // the replay window bounded by uniqueness, not by the ttl.
          expiresAt: Math.floor(now / 1000) + 300,
          uniqueId: crypto.randomUUID()
        });

        // RFC 7523 section 2.2: authenticate the token request with the
        // signed assertion.
        params.set('client_id', clientInformation.client_id);
        params.set('client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
        params.set('client_assertion', token);
      }
      break;

      // RFC 6749 section 4.1.3: public clients authenticate token requests
      // with their client_id alone. The MCP SDK prefers this method over its
      // own public-client handling whenever a provider defines it, so leaving
      // this case out sends token requests with no client identification.
      case 'none': {
        params.set('client_id', clientInformation.client_id);
      }
      break;
    }

  }

  /**
   * Returns `undefined` when no redirect URL was configured. The MCP SDK
   * reads that as a non-interactive provider (`client_credentials`,
   * `jwt-bearer`) and skips the authorization redirect leg.
   */
  get redirectUrl(): string | URL | undefined {
    return this._redirectUrl;
  }

  get clientMetadata(): OAuthClientMetadata {
    return this._metadata;
  }

  /**
   * This provider holds a single credential set, so the authorization-server
   * binding context is ignored (permitted by the MCP SDK contract).
   */
  clientInformation(ctx?: OAuthClientInformationContext): StoredOAuthClientInformation | undefined | Promise<StoredOAuthClientInformation | undefined> {
    if (this._clientId) {
      return { ...this.clientMetadata, client_id: this._clientId };
    }

    return undefined;
  }

  tokens(ctx?: OAuthClientInformationContext): Promise<StoredOAuthTokens | undefined> {
    if (!this.tokensStore) {
      throw new Error("OAuth tokens store not initialized");
    }
    return this.tokensStore.get(ctx);
  }

  saveTokens(tokens: StoredOAuthTokens, ctx?: OAuthClientInformationContext): void | Promise<void> {
    if (!this.tokensStore) {
      throw new Error("OAuth tokens store not initialized");
    }
    return this.tokensStore.save(tokens, ctx);
  }

  redirectToAuthorization(authorizationUrl: URL): void | Promise<void> {
    throw new Error('redirectToAuthorization not implemented');
  }

  saveCodeVerifier(codeVerifier: string): void | Promise<void> {
    if (!this.codeVerifierStore) {
      throw new Error("OAuth code verifier store not initialized");
    }
    return this.codeVerifierStore.save(codeVerifier);
  }

  codeVerifier(): string | Promise<string> {
    if (!this.codeVerifierStore) {
      throw new Error("OAuth code verifier store not initialized");
    }
    return this.codeVerifierStore.get();
  }
}
