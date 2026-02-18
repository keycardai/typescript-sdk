import { jest } from '@jest/globals';
import { BaseOAuthClientProvider } from './base.js';

describe('Base OAuth client provider', () => {

  describe('creation with client ID', () => {
    const provider = new BaseOAuthClientProvider({
        token_endpoint_auth_method: "private_key_jwt",
        jwks_uri: "https://client.example.com/jwks.json"
      }, 'https://client.example.com');

    it('should get client information', async () => {
      expect(await provider.clientInformation()).toStrictEqual({
        client_id: "https://client.example.com",
        token_endpoint_auth_method: "private_key_jwt",
        jwks_uri: "https://client.example.com/jwks.json"
      })
    });

    it('should get client metadata', async () => {
      expect(provider.clientMetadata).toStrictEqual({
        token_endpoint_auth_method: "private_key_jwt",
        jwks_uri: "https://client.example.com/jwks.json"
      })
    });
  }); // creation with client ID

  describe('OAuth token store', () => {

    describe('tokens', () => {

      it('should call token store', async () => {
        const mockTokensStore = {
          get: jest.fn(),
        };

        const provider = new BaseOAuthClientProvider({
          token_endpoint_auth_method: "client_secret_basic",
        });
        provider.tokensStore = mockTokensStore;

        const tokens = provider.tokens();
        expect(provider.tokensStore.get).toHaveBeenCalled();
      });

      it('should throw when not initialized', async () => {
        const provider = new BaseOAuthClientProvider({
          token_endpoint_auth_method: "client_secret_basic",
        });

        await expect(() => provider.tokens()).toThrow(
          'OAuth tokens store not initialized'
        );
      });

    });

    describe('saveTokens', () => {

      it('should call token store', async () => {
        const mockTokensStore = {
          save: jest.fn(),
        };

        const provider = new BaseOAuthClientProvider({
          token_endpoint_auth_method: "client_secret_basic",
        });
        provider.tokensStore = mockTokensStore;

        const tokens = {
          access_token: "2YotnFZFEjr1zCsicMWpAA",
          token_type: "Bearer"
        };
        provider.saveTokens(tokens);
        expect(provider.tokensStore.save).toHaveBeenCalledWith(tokens);
      });

      it('should throw when not initialized', async () => {
        const provider = new BaseOAuthClientProvider({
          token_endpoint_auth_method: "client_secret_basic",
        });

        const tokens = {
          access_token: "2YotnFZFEjr1zCsicMWpAA",
          token_type: "Bearer"
        }
        await expect(() => provider.saveTokens(tokens)).toThrow(
          'OAuth tokens store not initialized'
        );
      });

    });

  });

  describe('OAuth code verifier store', () => {

    describe('codeVerifier', () => {

      it('should call code verifier store', async () => {
        const mockCodeVerifierStore = {
          get: jest.fn(),
        };

        const provider = new BaseOAuthClientProvider({
          token_endpoint_auth_method: "client_secret_basic",
        });
        provider.codeVerifierStore = mockCodeVerifierStore;

        const codeVerifier = provider.codeVerifier();
        expect(provider.codeVerifierStore.get).toHaveBeenCalled();
      });

      it('should throw when not initialized', async () => {
        const provider = new BaseOAuthClientProvider({
          token_endpoint_auth_method: "client_secret_basic",
        });

        await expect(() => provider.codeVerifier()).toThrow(
          'OAuth code verifier store not initialized'
        );
      });

    });

    describe('saveCodeVerifier', () => {

      it('should call code verifier store', async () => {
        const mockCodeVerifierStore = {
          save: jest.fn(),
        };

        const provider = new BaseOAuthClientProvider({
          token_endpoint_auth_method: "client_secret_basic",
        });
        provider.codeVerifierStore = mockCodeVerifierStore;

        const codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        provider.saveCodeVerifier(codeVerifier);
        expect(provider.codeVerifierStore.save).toHaveBeenCalledWith(codeVerifier);
      });

      it('should throw when not initialized', async () => {
        const provider = new BaseOAuthClientProvider({
          token_endpoint_auth_method: "client_secret_basic",
        });

        const codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        await expect(() => provider.saveCodeVerifier(codeVerifier)).toThrow(
          'OAuth code verifier store not initialized'
        );
      });

    });

  });

});
