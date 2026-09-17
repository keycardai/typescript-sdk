import { jest } from '@jest/globals';
import { beginAuthorization, completeAuthorization, refreshAuthorization } from './webApp.js';
import { AuthorizationDeniedError, OAuthError, RefreshGrantError, StateMismatchError } from './errors.js';

const ISSUER = 'https://auth.example.com';
const AUTHORIZE_ENDPOINT = `${ISSUER}/authorize`;
const TOKEN_ENDPOINT = `${ISSUER}/token`;
const REDIRECT_URI = 'https://app.example.com/callback';

const METADATA = {
  issuer: ISSUER,
  authorization_endpoint: AUTHORIZE_ENDPOINT,
  token_endpoint: TOKEN_ENDPOINT,
};

type FetchCall = { url: string; init?: RequestInit };

function mockFetch(responder: (url: string, init?: RequestInit) => Response): FetchCall[] {
  const calls: FetchCall[] = [];
  globalThis.fetch = jest.fn(async (input: unknown, init?: unknown) => {
    const url = String(input);
    calls.push({ url, init: init as RequestInit | undefined });
    return responder(url, init as RequestInit | undefined);
  }) as unknown as typeof fetch;
  return calls;
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

describe('web-app flow', () => {
  let originalFetch: typeof fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  describe('beginAuthorization', () => {
    it('discovers the authorization endpoint and returns the flow state', async () => {
      mockFetch(() => jsonResponse(200, METADATA));

      const flow = await beginAuthorization(ISSUER, {
        clientId: 'client-123',
        redirectUri: REDIRECT_URI,
        scopes: ['openid', 'profile'],
      });

      const url = new URL(flow.url);
      expect(`${url.origin}${url.pathname}`).toBe(AUTHORIZE_ENDPOINT);
      expect(url.searchParams.get('response_type')).toBe('code');
      expect(url.searchParams.get('client_id')).toBe('client-123');
      expect(url.searchParams.get('redirect_uri')).toBe(REDIRECT_URI);
      expect(url.searchParams.get('scope')).toBe('openid profile');
      expect(url.searchParams.get('state')).toBe(flow.state);
      expect(url.searchParams.get('code_challenge_method')).toBe('S256');
      expect(flow.codeVerifier).toHaveLength(128);
    });

    it('embeds the challenge derived from the returned verifier', async () => {
      mockFetch(() => jsonResponse(200, METADATA));

      const flow = await beginAuthorization(ISSUER, {
        clientId: 'client-123',
        redirectUri: REDIRECT_URI,
      });

      const digest = await crypto.subtle.digest(
        'SHA-256',
        new TextEncoder().encode(flow.codeVerifier),
      );
      const expected = Buffer.from(digest)
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
      expect(new URL(flow.url).searchParams.get('code_challenge')).toBe(expected);
    });

    it('emits one resource parameter per entry of the resources list', async () => {
      mockFetch(() => jsonResponse(200, METADATA));

      const resources = ['https://api.example.com', 'https://files.example.com'];
      const flow = await beginAuthorization(ISSUER, {
        clientId: 'client-123',
        redirectUri: REDIRECT_URI,
        resources,
      });

      expect(new URL(flow.url).searchParams.getAll('resource')).toEqual(resources);
      expect(flow.resources).toEqual(resources);
    });

    it('carries an empty resources list when begin was called without resources', async () => {
      mockFetch(() => jsonResponse(200, METADATA));

      const flow = await beginAuthorization(ISSUER, {
        clientId: 'client-123',
        redirectUri: REDIRECT_URI,
      });

      expect(flow.resources).toEqual([]);
      expect(new URL(flow.url).searchParams.getAll('resource')).toEqual([]);
    });

    it('skips discovery when pre-discovered metadata is supplied', async () => {
      const calls = mockFetch(() => jsonResponse(200, METADATA));

      const flow = await beginAuthorization(ISSUER, {
        clientId: 'client-123',
        redirectUri: REDIRECT_URI,
        metadata: METADATA,
      });

      expect(calls).toHaveLength(0);
      expect(flow.url.startsWith(AUTHORIZE_ENDPOINT)).toBe(true);
    });
  });

  describe('completeAuthorization', () => {
    const flowState = {
      state: 'stored-state',
      codeVerifier: 'stored-verifier',
      clientId: 'client-123',
      redirectUri: REDIRECT_URI,
      metadata: METADATA,
    };

    it('exchanges the code with the stored verifier and redirect URI', async () => {
      const calls = mockFetch(() =>
        jsonResponse(200, { access_token: 'at', token_type: 'Bearer' }),
      );

      const token = await completeAuthorization(ISSUER, {
        ...flowState,
        callbackParams: { code: 'auth-code', state: 'stored-state' },
      });

      expect(token.accessToken).toBe('at');
      expect(calls).toHaveLength(1);
      expect(calls[0].url).toBe(TOKEN_ENDPOINT);
      const body = new URLSearchParams(String(calls[0].init?.body));
      expect(body.get('grant_type')).toBe('authorization_code');
      expect(body.get('code')).toBe('auth-code');
      expect(body.get('code_verifier')).toBe('stored-verifier');
      expect(body.get('redirect_uri')).toBe(REDIRECT_URI);
      expect(body.get('client_id')).toBe('client-123');
    });

    it('never sends a resource parameter on the token request', async () => {
      const calls = mockFetch(() =>
        jsonResponse(200, { access_token: 'at', token_type: 'Bearer' }),
      );

      await completeAuthorization(ISSUER, {
        ...flowState,
        callbackParams: { code: 'auth-code', state: 'stored-state' },
      });

      const body = new URLSearchParams(String(calls[0].init?.body));
      expect(body.getAll('resource')).toEqual([]);
      expect(body.has('resource')).toBe(false);
    });

    it('accepts URLSearchParams callback params', async () => {
      mockFetch(() => jsonResponse(200, { access_token: 'at', token_type: 'Bearer' }));

      const token = await completeAuthorization(ISSUER, {
        ...flowState,
        callbackParams: new URLSearchParams({ code: 'auth-code', state: 'stored-state' }),
      });

      expect(token.accessToken).toBe('at');
    });

    it('rejects a denied callback before any token request', async () => {
      const calls = mockFetch(() => jsonResponse(200, {}));

      const error = await completeAuthorization(ISSUER, {
        ...flowState,
        callbackParams: {
          error: 'access_denied',
          error_description: 'User denied the request',
          state: 'stored-state',
        },
      }).catch((e: unknown) => e);

      expect(error).toBeInstanceOf(AuthorizationDeniedError);
      expect(error).toMatchObject({
        errorCode: 'access_denied',
        errorDescription: 'User denied the request',
      });
      expect(calls).toHaveLength(0);
    });

    it('rejects a mismatched state before any token request', async () => {
      const calls = mockFetch(() => jsonResponse(200, {}));

      await expect(
        completeAuthorization(ISSUER, {
          ...flowState,
          callbackParams: { code: 'auth-code', state: 'other-state' },
        }),
      ).rejects.toBeInstanceOf(StateMismatchError);
      expect(calls).toHaveLength(0);
    });

    it('rejects a missing state before any token request', async () => {
      const calls = mockFetch(() => jsonResponse(200, {}));

      await expect(
        completeAuthorization(ISSUER, {
          ...flowState,
          callbackParams: { code: 'auth-code' },
        }),
      ).rejects.toBeInstanceOf(StateMismatchError);
      expect(calls).toHaveLength(0);
    });

    it('rejects a callback with no code', async () => {
      const calls = mockFetch(() => jsonResponse(200, {}));

      await expect(
        completeAuthorization(ISSUER, {
          ...flowState,
          callbackParams: { state: 'stored-state' },
        }),
      ).rejects.toMatchObject({ errorCode: 'invalid_request' });
      expect(calls).toHaveLength(0);
    });

    it('surfaces a token endpoint OAuth error', async () => {
      mockFetch(() => jsonResponse(400, { error: 'invalid_grant', error_description: 'expired' }));

      await expect(
        completeAuthorization(ISSUER, {
          ...flowState,
          callbackParams: { code: 'auth-code', state: 'stored-state' },
        }),
      ).rejects.toBeInstanceOf(OAuthError);
    });

    it('authenticates a confidential client with HTTP Basic and no client_id in the body', async () => {
      const calls = mockFetch(() =>
        jsonResponse(200, { access_token: 'at', token_type: 'Bearer' }),
      );

      await completeAuthorization(ISSUER, {
        ...flowState,
        clientSecret: 'shh',
        callbackParams: { code: 'auth-code', state: 'stored-state' },
      });

      const headers = calls[0].init?.headers as Record<string, string>;
      expect(headers['Authorization']).toBe(`Basic ${btoa('client-123:shh')}`);
      expect(new URLSearchParams(String(calls[0].init?.body)).has('client_id')).toBe(false);
    });

        failure = e;
      }

      expect(failure).toBeInstanceOf(RefreshGrantError);
      const error = failure as RefreshGrantError;
      expect(error.errorCode).toBe('invalid_response');
      expect(error.retryable).toBe(false);
      expect(error.status).toBe(200);
    });

    it('discovers the token endpoint when no metadata is supplied', async () => {
      const calls = mockFetch((url) =>
        url.includes('.well-known')
          ? jsonResponse(200, METADATA)
          : jsonResponse(200, { access_token: 'at', token_type: 'Bearer' }),
      );

      await completeAuthorization(ISSUER, {
        state: 'stored-state',
        codeVerifier: 'stored-verifier',
        clientId: 'client-123',
        redirectUri: REDIRECT_URI,
        callbackParams: { code: 'auth-code', state: 'stored-state' },
      });

      expect(calls[0].url).toContain('/.well-known/oauth-authorization-server');
      expect(calls[1].url).toBe(TOKEN_ENDPOINT);
    });
  });

  describe('refreshAuthorization', () => {
    it('posts grant_type=refresh_token and returns the rotated pair', async () => {
      const calls = mockFetch(() =>
        jsonResponse(200, {
          access_token: 'at-2',
          token_type: 'Bearer',
          expires_in: 3600,
          refresh_token: 'rt-2',
          scope: 'openid',
        }),
      );

      const token = await refreshAuthorization(ISSUER, {
        metadata: METADATA,
        refreshToken: 'rt-1',
        clientId: 'client-123',
        resources: ['https://api.example.com', 'https://files.example.com'],
        scopes: ['openid'],
      });

      expect(calls).toHaveLength(1);
      expect(calls[0].url).toBe(TOKEN_ENDPOINT);
      expect(calls[0].init?.method).toBe('POST');
      const body = new URLSearchParams(String(calls[0].init?.body));
      expect(body.get('grant_type')).toBe('refresh_token');
      expect(body.get('refresh_token')).toBe('rt-1');
      expect(body.get('scope')).toBe('openid');
      expect(body.getAll('resource')).toEqual(['https://api.example.com', 'https://files.example.com']);
      expect(token.accessToken).toBe('at-2');
      expect(token.refreshToken).toBe('rt-2');
      expect(token.expiresIn).toBe(3600);
    });

    it('authenticates a public client with client_id in the body and no secret', async () => {
      const calls = mockFetch(() => jsonResponse(200, { access_token: 'at', token_type: 'Bearer' }));

      await refreshAuthorization(ISSUER, {
        metadata: METADATA,
        refreshToken: 'rt-1',
        clientId: 'client-123',
      });

      const headers = calls[0].init?.headers as Record<string, string>;
      expect(headers['Authorization']).toBeUndefined();
      const body = new URLSearchParams(String(calls[0].init?.body));
      expect(body.get('client_id')).toBe('client-123');
      expect(body.has('client_secret')).toBe(false);
      expect(body.has('resource')).toBe(false);
      expect(body.has('scope')).toBe(false);
    });

    it('authenticates a confidential client with HTTP Basic', async () => {
      const calls = mockFetch(() => jsonResponse(200, { access_token: 'at', token_type: 'Bearer' }));

      await refreshAuthorization(ISSUER, {
        metadata: METADATA,
        refreshToken: 'rt-1',
        clientId: 'client-123',
        clientSecret: 'shh',
      });

      const headers = calls[0].init?.headers as Record<string, string>;
      expect(headers['Authorization']).toBe(`Basic ${btoa('client-123:shh')}`);
      const body = new URLSearchParams(String(calls[0].init?.body));
      expect(body.has('client_id')).toBe(false);
      expect(body.has('client_secret')).toBe(false);
    });

    it('maps invalid_grant to a non-retryable RefreshGrantError', async () => {
      mockFetch(() =>
        jsonResponse(400, { error: 'invalid_grant', error_description: 'refresh token revoked' }),
      );

      const failure = await refreshAuthorization(ISSUER, {
        metadata: METADATA,
        refreshToken: 'rt-1',
        clientId: 'client-123',
      }).catch((e: unknown) => e);

      expect(failure).toBeInstanceOf(RefreshGrantError);
      expect(failure).toBeInstanceOf(OAuthError);
      const error = failure as RefreshGrantError;
      expect(error.errorCode).toBe('invalid_grant');
      expect(error.message).toBe('refresh token revoked');
      expect(error.retryable).toBe(false);
      expect(error.status).toBe(400);
    });

    it('maps a 5xx to a retryable RefreshGrantError', async () => {
      mockFetch(() => new Response('upstream down', { status: 503 }));

      const failure = await refreshAuthorization(ISSUER, {
        metadata: METADATA,
        refreshToken: 'rt-1',
        clientId: 'client-123',
      }).catch((e: unknown) => e);

      expect(failure).toBeInstanceOf(RefreshGrantError);
      const error = failure as RefreshGrantError;
      expect(error.errorCode).toBe('invalid_response');
      expect(error.retryable).toBe(true);
      expect(error.status).toBe(503);
    });

    it('maps a transport failure to a retryable RefreshGrantError', async () => {
      globalThis.fetch = jest.fn(async () => {
        throw new TypeError('fetch failed');
      }) as unknown as typeof fetch;

      const failure = await refreshAuthorization(ISSUER, {
        metadata: METADATA,
        refreshToken: 'rt-1',
        clientId: 'client-123',
      }).catch((e: unknown) => e);

      expect(failure).toBeInstanceOf(RefreshGrantError);
      const error = failure as RefreshGrantError;
      expect(error.retryable).toBe(true);
      expect(error.cause).toBeInstanceOf(TypeError);
    });

    it('maps a non-JSON success body to a non-retryable RefreshGrantError', async () => {
      mockFetch(() =>
        new Response('<html>not json</html>', { status: 200, headers: { 'content-type': 'text/html' } }),
      );

      let failure: unknown;
      try {
        await refreshAuthorization(ISSUER, {
          metadata: METADATA,
          refreshToken: 'rt-1',
          clientId: 'client-123',
        });
      } catch (e) {
    it('discovers the token endpoint when no metadata is supplied', async () => {
      const calls = mockFetch((url) =>
        url.includes('.well-known')
          ? jsonResponse(200, METADATA)
          : jsonResponse(200, { access_token: 'at', token_type: 'Bearer' }),
      );

      await refreshAuthorization(ISSUER, { refreshToken: 'rt-1', clientId: 'client-123' });

      expect(calls[0].url).toContain('/.well-known/oauth-authorization-server');
      expect(calls[1].url).toBe(TOKEN_ENDPOINT);
    });
  });
});
