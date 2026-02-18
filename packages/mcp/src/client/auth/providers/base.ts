import { OAuthClientProvider } from '@modelcontextprotocol/sdk/client/auth.js';
import { OAuthClientMetadata, OAuthClientInformation, OAuthTokens, OAuthMetadata } from '@modelcontextprotocol/sdk/shared/auth.js';
import type { PrivateKeyring } from "@keycardai/oauth/keyring";
import { JSONWebTokenSigner } from "../signers/jwt.js";

export interface OAuthTokensStore {
  get(): Promise<OAuthTokens | undefined>;
  save(tokens: OAuthTokens): void | Promise<void>;
}

export interface OAuthCodeVerifierStore {
  get(): string | Promise<string>;
  save(codeVerifier: string): void | Promise<void>;
}



export class BaseOAuthClientProvider implements OAuthClientProvider {
  private _redirectUrl: string | URL | undefined;


  private _clientId: string | undefined;
  private _metadata: OAuthClientMetadata;
  protected privateKeyring: PrivateKeyring | undefined;
  protected tokensStore: OAuthTokensStore | undefined;
  protected codeVerifierStore: OAuthCodeVerifierStore | undefined;

  constructor(metadata: OAuthClientMetadata, clientId?: string) {
    this._clientId = clientId;
    this._metadata = metadata;

    // workaround to bind function to this context, since underlying
    // MCP library calls it without a context.
    this.addClientAuthentication = this.addClientAuthentication.bind(this);
  }

  async addClientAuthentication(
    headers: Headers,
    params: URLSearchParams,
    authorizationServerUrl: string | URL,
    metadata?: OAuthMetadata,
  ) {
    const clientInfo = await this.clientInformation();
    if (!clientInfo) {
      throw new Error("Client information not available for authentication");
    }
    const clientInformation = { ...this._metadata, ...clientInfo };
    const supportedMethods = metadata?.token_endpoint_auth_methods_supported ?? [];
    const authMethod = clientInformation.token_endpoint_auth_method || 'client_secret_basic';

    switch (authMethod) {
      case 'private_key_jwt': {
        if (!this.privateKeyring) {
          throw new Error("Private keyring not initialized");
        }

        const tokenUrl = metadata?.token_endpoint
          ? new URL(metadata.token_endpoint)
          : new URL("/token", authorizationServerUrl);
        const now = Date.now();
        const signer = new JSONWebTokenSigner(this.privateKeyring);
        const token = await signer.signToken({
          userId: clientInformation.client_id,
          resource: tokenUrl,
          issuedAt: Math.floor(now / 1000),
          expiresAt: Math.floor(now / 1000) + 60,
          uniqueId: crypto.randomUUID()
        });
      }
      break;
    }

  }

  get redirectUrl() {
    if (!this._redirectUrl) {
      throw new Error("Attempt to access redirectUrl before it was set");
    }
    return this._redirectUrl;
  }

  get clientMetadata(): OAuthClientMetadata {
    return this._metadata;
  }

  clientInformation(): OAuthClientInformation | undefined | Promise<OAuthClientInformation | undefined> {
    if (this._clientId) {
      return { ...this.clientMetadata, client_id: this._clientId };
    }

    return undefined;
  }

  tokens(): Promise<OAuthTokens | undefined> {
    if (!this.tokensStore) {
      throw new Error("OAuth tokens store not initialized");
    }
    return this.tokensStore.get();
  }

  saveTokens(tokens: OAuthTokens): void | Promise<void> {
    if (!this.tokensStore) {
      throw new Error("OAuth tokens store not initialized");
    }
    this.tokensStore.save(tokens);
  }

  redirectToAuthorization(authorizationUrl: URL): void | Promise<void> {
    throw new Error('redirectToAuthorization not implemented');
  }

  saveCodeVerifier(codeVerifier: string): void | Promise<void> {
    if (!this.codeVerifierStore) {
      throw new Error("OAuth code verifier store not initialized");
    }
    this.codeVerifierStore.save(codeVerifier);
  }

  codeVerifier(): string | Promise<string> {
    if (!this.codeVerifierStore) {
      throw new Error("OAuth code verifier store not initialized");
    }
    return this.codeVerifierStore.get();
  }
}
