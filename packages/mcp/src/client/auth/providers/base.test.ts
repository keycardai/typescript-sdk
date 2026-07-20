import { jest } from '@jest/globals';
import type { OAuthTokens } from '@modelcontextprotocol/sdk/shared/auth.js';
import { BaseOAuthClientProvider, type OAuthTokensStore, type OAuthCodeVerifierStore } from './base.js';

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

  describe('addClientAuthentication', () => {

    it('should send client_id for public clients', async () => {
      const provider = new BaseOAuthClientProvider({
        token_endpoint_auth_method: "none",
      }, 'client-123');

      const params = new URLSearchParams();
      await provider.addClientAuthentication(new Headers(), params, "https://auth.example.com");

      expect(params.get('client_id')).toBe('client-123');
    });

    it('should throw without client information', async () => {
      const provider = new BaseOAuthClientProvider({
        token_endpoint_auth_method: "none",
      });

      await expect(
        provider.addClientAuthentication(new Headers(), new URLSearchParams(), "https://auth.example.com")
      ).rejects.toThrow('Client information not available for authentication');
    });

  }); // addClientAuthentication

  describe('creation with options', () => {

    it('should return the redirect URL passed via options', () => {
      const provider = new BaseOAuthClientProvider({
        token_endpoint_auth_method: "client_secret_basic",
      }, undefined, {
        redirectUrl: "https://agent.example.com/oauth/callback",
      });

      expect(provider.redirectUrl).toBe("https://agent.example.com/oauth/callback");
    });

    it('should throw when redirect URL was not set', () => {
      const provider = new BaseOAuthClientProvider({
        token_endpoint_auth_method: "client_secret_basic",
      });

      expect(() => provider.redirectUrl).toThrow(
        'Attempt to access redirectUrl before it was set'
      );
    });

    it('should use stores passed via options', async () => {
      const mockTokensStore = {
        get: jest.fn(),
        save: jest.fn(),
      };
      const mockCodeVerifierStore = {
        get: jest.fn(),
        save: jest.fn(),
      };

      const provider = new BaseOAuthClientProvider({
        token_endpoint_auth_method: "client_secret_basic",
      }, undefined, {
        tokensStore: mockTokensStore,
        codeVerifierStore: mockCodeVerifierStore,
      });

      provider.tokens();
      expect(mockTokensStore.get).toHaveBeenCalled();

      provider.saveCodeVerifier("verifier");
      expect(mockCodeVerifierStore.save).toHaveBeenCalledWith("verifier");
    });

  }); // creation with options

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

      it('should complete the async store write before resolving', async () => {
        let stored: OAuthTokens | undefined;
        const slowTokensStore: OAuthTokensStore = {
          get: async () => stored,
          save: async (tokens) => {
            await new Promise((resolve) => setTimeout(resolve, 20));
            stored = tokens;
          },
        };

        const provider = new BaseOAuthClientProvider({
          token_endpoint_auth_method: "client_secret_basic",
        }, undefined, {
          tokensStore: slowTokensStore,
        });

        const tokens = {
          access_token: "2YotnFZFEjr1zCsicMWpAA",
          token_type: "Bearer"
        };
        await provider.saveTokens(tokens);
        expect(await provider.tokens()).toStrictEqual(tokens);
      });

      it('should propagate store save failures', async () => {
        const failingTokensStore: OAuthTokensStore = {
          get: async () => undefined,
          save: async () => {
            throw new Error('tokens store write failed');
          },
        };

        const provider = new BaseOAuthClientProvider({
          token_endpoint_auth_method: "client_secret_basic",
        }, undefined, {
          tokensStore: failingTokensStore,
        });

        await expect(provider.saveTokens({
          access_token: "2YotnFZFEjr1zCsicMWpAA",
          token_type: "Bearer"
        })).rejects.toThrow('tokens store write failed');
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

      it('should complete the async store write before resolving', async () => {
        let stored: string | undefined;
        const slowCodeVerifierStore: OAuthCodeVerifierStore = {
          get: async () => {
            if (stored === undefined) {
              throw new Error('code verifier not stored');
            }
            return stored;
          },
          save: async (codeVerifier) => {
            await new Promise((resolve) => setTimeout(resolve, 20));
            stored = codeVerifier;
          },
        };

        const provider = new BaseOAuthClientProvider({
          token_endpoint_auth_method: "client_secret_basic",
        }, undefined, {
          codeVerifierStore: slowCodeVerifierStore,
        });

        const codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        await provider.saveCodeVerifier(codeVerifier);
        expect(await provider.codeVerifier()).toBe(codeVerifier);
      });

      it('should propagate store save failures', async () => {
        const failingCodeVerifierStore: OAuthCodeVerifierStore = {
          get: async () => {
            throw new Error('code verifier not stored');
          },
          save: async () => {
            throw new Error('code verifier store write failed');
          },
        };

        const provider = new BaseOAuthClientProvider({
          token_endpoint_auth_method: "client_secret_basic",
        }, undefined, {
          codeVerifierStore: failingCodeVerifierStore,
        });

        await expect(
          provider.saveCodeVerifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
        ).rejects.toThrow('code verifier store write failed');
      });

    });

  });

});
