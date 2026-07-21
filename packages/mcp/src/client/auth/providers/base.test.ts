import { jest } from '@jest/globals';
import type { AuthorizationServerMetadata, OAuthDiscoveryState, StoredOAuthTokens } from '@modelcontextprotocol/client';
import type { PrivateKeyring } from '@keycardai/oauth/keyring';
import {
  BaseOAuthClientProvider,
  type OAuthTokensStore,
  type OAuthCodeVerifierStore,
  type OAuthDiscoveryStateStore,
} from './base.js';

// https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.2
const RFC7515_RS256_PRIVATE_KEY = {
  kty: "RSA",
  n: "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
  e: "AQAB",
  d: "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ",
  p: "4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc",
  q: "uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc",
  dp: "BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0",
  dq: "h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU",
  qi: "IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U"
}

const RFC7515_RS256_PUBLIC_KEY = {
  kty: "RSA",
  n: "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
  e: "AQAB"
}

function base64urlDecodeToJSON(segment: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));
}

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

    it('should attach a client assertion for private_key_jwt clients', async () => {
      const privateKey = await crypto.subtle.importKey(
        'jwk',
        RFC7515_RS256_PRIVATE_KEY,
        {
          name: 'RSASSA-PKCS1-v1_5',
          hash: 'SHA-256',
        },
        true,
        ['sign']
      );
      const publicKey = await crypto.subtle.importKey(
        'jwk',
        RFC7515_RS256_PUBLIC_KEY,
        {
          name: 'RSASSA-PKCS1-v1_5',
          hash: 'SHA-256',
        },
        true,
        ['verify']
      );
      // The keyring issuer intentionally differs from the client ID: the
      // assertion must carry iss = client_id, not the keyring fallback.
      const privateKeyring: PrivateKeyring = {
        key: async () => ({ issuer: 'https://keyring.example.com', kid: 'RjEwOwOA', key: privateKey }),
      };

      const provider = new BaseOAuthClientProvider({
        token_endpoint_auth_method: "private_key_jwt",
        jwks_uri: "https://client.example.com/jwks.json",
      }, 'https://client.example.com', { privateKeyring });

      const serverMetadata: AuthorizationServerMetadata = {
        issuer: "https://auth.example.com",
        authorization_endpoint: "https://auth.example.com/authorize",
        token_endpoint: "https://auth.example.com/token",
        response_types_supported: ["code"],
      };

      const params = new URLSearchParams();
      await provider.addClientAuthentication(new Headers(), params, "https://auth.example.com", serverMetadata);

      expect(params.get('client_id')).toBe('https://client.example.com');
      expect(params.get('client_assertion_type')).toBe('urn:ietf:params:oauth:client-assertion-type:jwt-bearer');

      const assertion = params.get('client_assertion');
      expect(assertion).not.toBeNull();
      const [headerSegment, payloadSegment, signatureSegment] = String(assertion).split('.');

      const signatureValid = await crypto.subtle.verify(
        { name: 'RSASSA-PKCS1-v1_5' },
        publicKey,
        Buffer.from(signatureSegment, 'base64url'),
        Buffer.from(`${headerSegment}.${payloadSegment}`, 'utf8')
      );
      // The client assertion signature must verify against the client public key.
      expect(signatureValid).toBe(true);

      const claims = base64urlDecodeToJSON(payloadSegment);
      expect(claims).toMatchObject({
        iss: 'https://client.example.com',
        sub: 'https://client.example.com',
        aud: 'https://auth.example.com/token',
      });
      expect(typeof claims.jti).toBe('string');
      expect(typeof claims.iat).toBe('number');
      expect(claims.exp).toBeGreaterThan(Number(claims.iat));
    });

    it('should use the url argument as assertion audience when metadata is absent', async () => {
      const privateKey = await crypto.subtle.importKey(
        'jwk',
        RFC7515_RS256_PRIVATE_KEY,
        {
          name: 'RSASSA-PKCS1-v1_5',
          hash: 'SHA-256',
        },
        true,
        ['sign']
      );
      const privateKeyring: PrivateKeyring = {
        key: async () => ({ issuer: 'https://keyring.example.com', kid: 'RjEwOwOA', key: privateKey }),
      };

      const provider = new BaseOAuthClientProvider({
        token_endpoint_auth_method: "private_key_jwt",
        jwks_uri: "https://client.example.com/jwks.json",
      }, 'https://client.example.com', { privateKeyring });

      // The MCP SDK passes the token endpoint URL being called as the url
      // argument, so the assertion audience must be that URL when no
      // server metadata is supplied.
      const params = new URLSearchParams();
      await provider.addClientAuthentication(new Headers(), params, "https://auth.example.com/token");

      const assertion = params.get('client_assertion');
      expect(assertion).not.toBeNull();
      const claims = base64urlDecodeToJSON(String(assertion).split('.')[1]);
      expect(claims).toMatchObject({
        iss: 'https://client.example.com',
        sub: 'https://client.example.com',
        aud: 'https://auth.example.com/token',
      });
    });

    it('should throw for private_key_jwt without a private keyring', async () => {
      const provider = new BaseOAuthClientProvider({
        token_endpoint_auth_method: "private_key_jwt",
      }, 'https://client.example.com');

      await expect(
        provider.addClientAuthentication(new Headers(), new URLSearchParams(), "https://auth.example.com")
      ).rejects.toThrow('Private keyring not initialized');
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

    it('should return undefined when redirect URL was not set', () => {
      const provider = new BaseOAuthClientProvider({
        token_endpoint_auth_method: "client_secret_basic",
      });

      // The MCP SDK reads an undefined redirectUrl as a non-interactive
      // provider (client_credentials, jwt-bearer) and skips the
      // authorization redirect leg.
      expect(provider.redirectUrl).toBeUndefined();
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
        expect(provider.tokensStore.save).toHaveBeenCalledWith(tokens, undefined);
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

    describe('authorization server binding context', () => {

      it('should forward the context to the store on reads and writes', async () => {
        const mockTokensStore = {
          get: jest.fn<OAuthTokensStore['get']>(async () => undefined),
          save: jest.fn<OAuthTokensStore['save']>(async () => undefined),
        };

        const provider = new BaseOAuthClientProvider({
          token_endpoint_auth_method: "client_secret_basic",
        }, undefined, {
          tokensStore: mockTokensStore,
        });

        const ctx = { issuer: "https://auth.example.com" };
        const tokens: StoredOAuthTokens = {
          access_token: "2YotnFZFEjr1zCsicMWpAA",
          token_type: "Bearer",
          issuer: "https://auth.example.com",
        };

        await provider.tokens(ctx);
        expect(mockTokensStore.get).toHaveBeenCalledWith(ctx);

        await provider.saveTokens(tokens, ctx);
        expect(mockTokensStore.save).toHaveBeenCalledWith(tokens, ctx);
      });

    });

  });

  describe('OAuth discovery state store', () => {

    const discoveryState: OAuthDiscoveryState = {
      authorizationServerUrl: "https://auth.example.com",
      resourceMetadataUrl: "https://mcp.example.com/.well-known/oauth-protected-resource",
    };

    it('should not define the discovery state methods without a store', () => {
      const provider = new BaseOAuthClientProvider({
        token_endpoint_auth_method: "client_secret_basic",
      });

      // The MCP SDK fails the authorization callback leg when
      // saveDiscoveryState is defined but no recorded state can be read
      // back, so a provider without a store must not define the methods.
      expect(provider.saveDiscoveryState).toBeUndefined();
      expect(provider.discoveryState).toBeUndefined();
    });

    it('should delegate to the store passed via options', async () => {
      const mockDiscoveryStateStore = {
        get: jest.fn<OAuthDiscoveryStateStore['get']>(async () => discoveryState),
        save: jest.fn<OAuthDiscoveryStateStore['save']>(async () => undefined),
      };

      const provider = new BaseOAuthClientProvider({
        token_endpoint_auth_method: "client_secret_basic",
      }, undefined, {
        discoveryStateStore: mockDiscoveryStateStore,
      });

      await provider.saveDiscoveryState?.(discoveryState);
      expect(mockDiscoveryStateStore.save).toHaveBeenCalledWith(discoveryState);

      expect(await provider.discoveryState?.()).toStrictEqual(discoveryState);
      expect(mockDiscoveryStateStore.get).toHaveBeenCalled();
    });

    it('should complete the async store write before resolving', async () => {
      let stored: OAuthDiscoveryState | undefined;
      const slowDiscoveryStateStore: OAuthDiscoveryStateStore = {
        get: async () => stored,
        save: async (state) => {
          await new Promise((resolve) => setTimeout(resolve, 20));
          stored = state;
        },
      };

      const provider = new BaseOAuthClientProvider({
        token_endpoint_auth_method: "client_secret_basic",
      }, undefined, {
        discoveryStateStore: slowDiscoveryStateStore,
      });

      await provider.saveDiscoveryState?.(discoveryState);
      expect(await provider.discoveryState?.()).toStrictEqual(discoveryState);
    });

    it('should propagate store save failures', async () => {
      const failingDiscoveryStateStore: OAuthDiscoveryStateStore = {
        get: async () => undefined,
        save: async () => {
          throw new Error('discovery state store write failed');
        },
      };

      const provider = new BaseOAuthClientProvider({
        token_endpoint_auth_method: "client_secret_basic",
      }, undefined, {
        discoveryStateStore: failingDiscoveryStateStore,
      });

      await expect(provider.saveDiscoveryState?.(discoveryState)).rejects.toThrow(
        'discovery state store write failed'
      );
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
