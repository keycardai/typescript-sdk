import { jest } from '@jest/globals';
import {
  generateCodeVerifier,
  generateCodeChallenge,
  generatePkcePair,
  exchangeAuthorizationCode,
  authenticate,
} from './pkce.js';
import { ConfigurationError, OAuthError } from './errors.js';
import type { ApplicationCredential } from './credentials.js';
import { WebIdentity } from './server/webIdentity.js';
import { WorkloadIdentity } from './server/workloadIdentity.js';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const ISSUER = 'https://auth.example.com';
const TOKEN_ENDPOINT = 'https://auth.example.com/token';

function metadataResponse(extra: Record<string, unknown> = {}): Response {
  return new Response(
    JSON.stringify({ issuer: ISSUER, token_endpoint: TOKEN_ENDPOINT, ...extra }),
    { status: 200, headers: { 'content-type': 'application/json' } },
  );
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

// =============================================================================
// Primitive tests
// =============================================================================

describe('generateCodeVerifier', () => {
  it('returns a 128-character base64url string with no padding by default', () => {
    const verifier = generateCodeVerifier();
    expect(verifier).toHaveLength(128);
    expect(verifier).toMatch(/^[A-Za-z0-9\-_]+$/);
    expect(verifier).not.toContain('=');
  });

  it('honors an explicit length within the RFC 7636 range', () => {
    expect(generateCodeVerifier(43)).toHaveLength(43);
    expect(generateCodeVerifier(64)).toHaveLength(64);
  });

  it('rejects lengths outside the RFC 7636 43-128 range', () => {
    expect(() => generateCodeVerifier(42)).toThrow(RangeError);
    expect(() => generateCodeVerifier(129)).toThrow(RangeError);
  });

  it('returns a different value on each call', () => {
    expect(generateCodeVerifier()).not.toBe(generateCodeVerifier());
  });
});

describe('generateCodeChallenge', () => {
  it('RFC 7636 Appendix B S256 test vector', async () => {
    const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    const challenge = await generateCodeChallenge(verifier, 'S256');
    expect(challenge).toBe('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
  });

  it('defaults to S256', async () => {
    const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    const challenge = await generateCodeChallenge(verifier);
    expect(challenge).toBe('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
  });

  it('plain method returns the verifier unchanged', async () => {
    const verifier = 'some-verifier-string';
    expect(await generateCodeChallenge(verifier, 'plain')).toBe(verifier);
  });
});

describe('generatePkcePair', () => {
  it('returns internally consistent verifier and challenge', async () => {
    const pair = await generatePkcePair();
    const expectedChallenge = await generateCodeChallenge(pair.codeVerifier, 'S256');
    expect(pair.codeChallenge).toBe(expectedChallenge);
    expect(pair.codeChallengeMethod).toBe('S256');
  });

  it('uses plain when requested', async () => {
    const pair = await generatePkcePair('plain');
    expect(pair.codeChallenge).toBe(pair.codeVerifier);
    expect(pair.codeChallengeMethod).toBe('plain');
  });
});

// =============================================================================
// exchangeAuthorizationCode
// =============================================================================

describe('exchangeAuthorizationCode', () => {
  let originalFetch: typeof fetch;
  let fetchMock: jest.Mock;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
    fetchMock = jest.fn();
    globalThis.fetch = fetchMock as unknown as typeof fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('returns a TokenResponse on success', async () => {
    fetchMock
      .mockImplementationOnce(async () => metadataResponse())
      .mockImplementationOnce(async () =>
        jsonResponse(200, {
          access_token: 'tok-123',
          token_type: 'Bearer',
          expires_in: 3600,
          scope: 'read write',
        }),
      );

    const result = await exchangeAuthorizationCode(ISSUER, 'auth-code-abc', {
      codeVerifier: 'verifier-xyz',
      redirectUri: 'http://localhost:8080/callback',
      clientId: 'my-client',
    });

    expect(result.accessToken).toBe('tok-123');
    expect(result.tokenType).toBe('Bearer');
    expect(result.expiresIn).toBe(3600);
    expect(result.scope).toEqual(['read', 'write']);
  });

  it('throws OAuthError on RFC 6749 error response', async () => {
    fetchMock
      .mockImplementationOnce(async () => metadataResponse())
      .mockImplementationOnce(async () =>
        jsonResponse(400, {
          error: 'invalid_grant',
          error_description: 'Authorization code expired',
        }),
      );

    let thrown: unknown;
    try {
      await exchangeAuthorizationCode(ISSUER, 'stale-code', {
        codeVerifier: 'v',
        redirectUri: 'http://localhost:8080/callback',
      });
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(OAuthError);
    expect((thrown as OAuthError).errorCode).toBe('invalid_grant');
    expect((thrown as OAuthError).message).toBe('Authorization code expired');
    expect((thrown as OAuthError).errorDescription).toBe('Authorization code expired');
    expect((thrown as OAuthError).reason).toBeUndefined();
  });

  it('exposes the reason from an RFC 6749 error response unchanged', async () => {
    fetchMock
      .mockImplementationOnce(async () => metadataResponse())
      .mockImplementationOnce(async () =>
        jsonResponse(400, { error: 'invalid_grant', error_description: 'Denied', reason: 'custom_denial' }),
      );

    await expect(
      exchangeAuthorizationCode(ISSUER, 'code', {
        codeVerifier: 'v',
        redirectUri: 'http://localhost:8080/callback',
      }),
    ).rejects.toMatchObject({ errorCode: 'invalid_grant', reason: 'custom_denial', errorDescription: 'Denied' });
  });

  it('throws when the AS does not advertise token_endpoint', async () => {
    fetchMock.mockImplementationOnce(async () =>
      new Response(
        JSON.stringify({ issuer: ISSUER, authorization_endpoint: 'https://auth.example.com/auth' }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      ),
    );

    await expect(
      exchangeAuthorizationCode(ISSUER, 'code', {
        codeVerifier: 'v',
        redirectUri: 'http://localhost:8080/callback',
      }),
    ).rejects.toThrow(ConfigurationError);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('sends Basic auth header when clientId and clientSecret are provided', async () => {
    fetchMock
      .mockImplementationOnce(async () => metadataResponse())
      .mockImplementationOnce(async () =>
        jsonResponse(200, { access_token: 'tok', token_type: 'bearer' }),
      );

    await exchangeAuthorizationCode(ISSUER, 'code', {
      codeVerifier: 'v',
      redirectUri: 'http://localhost:8080/callback',
      clientId: 'id',
      clientSecret: 'secret',
    });

    const [, tokenCall] = fetchMock.mock.calls;
    const headers = ((tokenCall![1] as RequestInit).headers) as Record<string, string>;
    expect(headers['Authorization']).toBe(`Basic ${btoa('id:secret')}`);
  });

  describe('with a credential', () => {
    const credential = (): ApplicationCredential => ({
      getAuth: () => null,
      prepareTokenExchangeRequest: async () => ({ subjectToken: 'unused' }),
      clientAuthentication: jest.fn(async (_issuer: string, endpoint: string) => ({
        headers: { 'X-Client-Auth': `header-for:${endpoint}` },
        form: {
          client_assertion: `assertion-for:${endpoint}`,
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        },
      })),
    });
    const base = { codeVerifier: 'v', redirectUri: 'http://localhost:8080/callback' };

    it('sends the credential headers and form fields', async () => {
      const cred = credential();
      fetchMock
        .mockImplementationOnce(async () => metadataResponse())
        .mockImplementationOnce(async () => jsonResponse(200, { access_token: 'tok', token_type: 'Bearer' }));

      await exchangeAuthorizationCode(ISSUER, 'code', { ...base, credential: cred });

      const [, tokenCall] = fetchMock.mock.calls;
      const init = tokenCall![1] as RequestInit;
      expect(init.headers).toEqual({
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-Client-Auth': `header-for:${TOKEN_ENDPOINT}`,
      });
      expect([...new URLSearchParams(String(init.body)).entries()]).toEqual([
        ['grant_type', 'authorization_code'],
        ['code', 'code'],
        ['code_verifier', 'v'],
        ['redirect_uri', 'http://localhost:8080/callback'],
        ['client_assertion', `assertion-for:${TOKEN_ENDPOINT}`],
        ['client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'],
      ]);
      expect(cred.clientAuthentication).toHaveBeenCalledWith(ISSUER, TOKEN_ENDPOINT);
    });

    it.each([
      { name: 'credential together with clientId', options: { credential: credential(), clientId: 'id' } },
      { name: 'credential together with clientSecret', options: { credential: credential(), clientSecret: 'shh' } },
      {
        name: 'a credential without clientAuthentication',
        options: {
          credential: {
            getAuth: () => null,
            prepareTokenExchangeRequest: async () => ({ subjectToken: 'unused' }),
          },
        },
      },
      {
        name: 'a WorkloadIdentity without clientId',
        options: { credential: new WorkloadIdentity(async () => 'platform-jwt') },
      },
    ])('$name throws ConfigurationError before any request', async ({ options }) => {
      await expect(
        exchangeAuthorizationCode(ISSUER, 'code', { ...base, ...options }),
      ).rejects.toThrow(ConfigurationError);
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it('throws the credential error as is and sends no token request', async () => {
      const failure = new Error('token source unavailable');
      fetchMock.mockImplementationOnce(async () => metadataResponse());

      await expect(
        exchangeAuthorizationCode(ISSUER, 'code', {
          ...base,
          credential: {
            getAuth: () => null,
            prepareTokenExchangeRequest: async () => ({ subjectToken: 'unused' }),
            clientAuthentication: async () => {
              throw failure;
            },
          },
        }),
      ).rejects.toBe(failure);
      expect(fetchMock).toHaveBeenCalledTimes(1);
    });

    describe('WebIdentity', () => {
      let storageDir: string;

      beforeEach(() => {
        storageDir = mkdtempSync(join(tmpdir(), 'pkce-webidentity-'));
      });

      afterEach(() => {
        rmSync(storageDir, { recursive: true, force: true });
      });

      it('sends an assertion whose aud is the token endpoint and no Basic header', async () => {
        fetchMock
          .mockImplementationOnce(async () => metadataResponse())
          .mockImplementationOnce(async () => jsonResponse(200, { access_token: 'tok', token_type: 'Bearer' }));

        await exchangeAuthorizationCode(ISSUER, 'code', {
          ...base,
          credential: new WebIdentity({ clientId: 'cred-abc', storageDir }),
        });

        const [, tokenCall] = fetchMock.mock.calls;
        const init = tokenCall![1] as RequestInit;
        expect((init.headers as Record<string, string>)['Authorization']).toBeUndefined();
        const body = new URLSearchParams(String(init.body));
        expect(body.get('client_assertion_type')).toBe('urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
        const payload = JSON.parse(
          Buffer.from(body.get('client_assertion')!.split('.')[1], 'base64url').toString(),
        ) as Record<string, unknown>;
        expect(payload.aud).toBe(TOKEN_ENDPOINT);
      });
    });
  });
});

// =============================================================================
// authenticate() — Node.js integration
// =============================================================================

describe('authenticate', () => {
  let originalFetch: typeof fetch;
  let fetchMock: jest.Mock;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
    fetchMock = jest.fn();
    globalThis.fetch = fetchMock as unknown as typeof fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('resolves when the loopback server receives a valid authorization code', async () => {
    const testPort = 19870;
    const AUTH_ENDPOINT = 'https://auth.example.com/authorize';

    fetchMock.mockImplementation(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.includes('/.well-known/')) {
        return new Response(
          JSON.stringify({
            issuer: ISSUER,
            token_endpoint: TOKEN_ENDPOINT,
            authorization_endpoint: AUTH_ENDPOINT,
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      return jsonResponse(200, { access_token: 'pkce-tok', token_type: 'bearer' });
    });

    let authorizeUrl: string | undefined;
    const authPromise = authenticate(ISSUER, {
      clientId: 'my-client',
      port: testPort,
      timeoutMs: 5000,
      openBrowser: (url) => {
        authorizeUrl = url;
      },
    });

    // Give the loopback server time to start. 250ms is conservative but
    // avoids ECONNREFUSED flakes on loaded CI machines without needing a
    // TCP-probe helper.
    await new Promise((r) => setTimeout(r, 250));

    expect(authorizeUrl).toBeDefined();
    const state = new URL(authorizeUrl!).searchParams.get('state');
    expect(state).toBeTruthy();

    // Simulate the browser being redirected back with an authorization code.
    // Use the real fetch (saved before mocking) so it actually hits the loopback server.
    await originalFetch(
      `http://localhost:${testPort}/callback?code=auth-code-xyz&state=${encodeURIComponent(state!)}`,
    );

    const result = await authPromise;
    expect(result.accessToken).toBe('pkce-tok');
  }, 8000);

  // Node's default server keep-alive timeout is 5 seconds. The 3 second test
  // timeout fails the test if the socket stays open, instead of leaving an open
  // handle that hangs Jest on exit.
  it('closes the callback connection after the response', async () => {
    const testPort = 19873;
    fetchMock.mockImplementation(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.includes('/.well-known/')) {
        return metadataResponse({ authorization_endpoint: 'https://auth.example.com/authorize' });
      }
      return jsonResponse(200, { access_token: 'pkce-tok', token_type: 'bearer' });
    });

    let authorizeUrl: string | undefined;
    const authPromise = authenticate(ISSUER, {
      clientId: 'my-client',
      port: testPort,
      timeoutMs: 2000,
      openBrowser: (url) => {
        authorizeUrl = url;
      },
    });
    await new Promise((r) => setTimeout(r, 250));
    const state = new URL(authorizeUrl!).searchParams.get('state')!;

    const { Agent, request } = await import('node:http');
    const agent = new Agent({ keepAlive: true });
    try {
      let socketClosed!: Promise<void>;
      const connection = await new Promise<string | undefined>((resolve, reject) => {
        const req = request(
          `http://localhost:${testPort}/callback?code=auth-code-xyz&state=${encodeURIComponent(state)}`,
          { agent },
          (res) => {
            res.resume();
            resolve(res.headers.connection);
          },
        );
        req.on('socket', (socket) => {
          socketClosed = new Promise((r) => socket.once('close', () => r()));
        });
        req.on('error', reject);
        req.end();
      });

      expect(connection).toBe('close');
      await socketClosed;
      expect((await authPromise).accessToken).toBe('pkce-tok');
    } finally {
      agent.destroy();
    }
  }, 3000);

  it('throws ConfigurationError before opening a browser when the AS does not advertise authorization_endpoint', async () => {
    fetchMock.mockImplementationOnce(async () =>
      new Response(JSON.stringify({ issuer: ISSUER, token_endpoint: TOKEN_ENDPOINT }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
    );
    const openBrowser = jest.fn();

    await expect(
      authenticate(ISSUER, { clientId: 'my-client', port: 19875, timeoutMs: 1000, openBrowser }),
    ).rejects.toThrow(ConfigurationError);
    expect(openBrowser).not.toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('throws ConfigurationError before any request when credential is set with clientSecret', async () => {
    const openBrowser = jest.fn();
    const credential: ApplicationCredential = {
      getAuth: () => null,
      prepareTokenExchangeRequest: async () => ({ subjectToken: 'unused' }),
      clientAuthentication: async () => ({ headers: {}, form: {} }),
    };

    await expect(
      authenticate(ISSUER, { clientId: 'my-client', clientSecret: 'shh', credential, openBrowser }),
    ).rejects.toThrow(ConfigurationError);
    expect(openBrowser).not.toHaveBeenCalled();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('throws ConfigurationError before any request for a WorkloadIdentity without clientId', async () => {
    const openBrowser = jest.fn();

    await expect(
      authenticate(ISSUER, {
        clientId: 'my-client',
        credential: new WorkloadIdentity(async () => 'platform-jwt'),
        openBrowser,
      }),
    ).rejects.toThrow(ConfigurationError);
    expect(openBrowser).not.toHaveBeenCalled();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('rejects when the redirect carries a wrong or missing state', async () => {
    const testPort = 19872;

    fetchMock.mockImplementation(async () =>
      new Response(
        JSON.stringify({
          issuer: ISSUER,
          token_endpoint: TOKEN_ENDPOINT,
          authorization_endpoint: 'https://auth.example.com/authorize',
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      ),
    );

    const authPromise = authenticate(ISSUER, {
      clientId: 'my-client',
      port: testPort,
      timeoutMs: 5000,
      openBrowser: () => {},
    });

    await new Promise((r) => setTimeout(r, 250));

    // Attach the rejection handler before triggering the redirect so the
    // rejection is never unhandled.
    const assertion = expect(authPromise).rejects.toThrow(/State mismatch/);
    await originalFetch(
      `http://localhost:${testPort}/callback?code=auth-code-xyz&state=forged-state`,
    );
    await assertion;
  }, 8000);

  it('rejects with a timeout error when no redirect arrives', async () => {
    const testPort = 19871;

    fetchMock.mockImplementation(async () =>
      new Response(
        JSON.stringify({
          issuer: ISSUER,
          token_endpoint: TOKEN_ENDPOINT,
          authorization_endpoint: 'https://auth.example.com/authorize',
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      ),
    );

    await expect(
      authenticate(ISSUER, { clientId: 'my-client', port: testPort, timeoutMs: 200, openBrowser: () => {} }),
    ).rejects.toThrow(/timed out/);
  }, 3000);
});

describe('buildAuthorizeUrl', () => {
  it('builds a complete authorization URL with all parameters', async () => {
    const { buildAuthorizeUrl } = await import('./pkce.js');
    const url = new URL(
      buildAuthorizeUrl('https://auth.example.com/authorize', {
        clientId: 'cli-tool',
        redirectUri: 'http://localhost:8765/callback',
        codeChallenge: 'challenge-abc',
        state: 'state-xyz',
        scope: 'read write',
        resource: 'https://api.example.com',
      }),
    );
    expect(url.origin + url.pathname).toBe('https://auth.example.com/authorize');
    expect(url.searchParams.get('response_type')).toBe('code');
    expect(url.searchParams.get('client_id')).toBe('cli-tool');
    expect(url.searchParams.get('redirect_uri')).toBe('http://localhost:8765/callback');
    expect(url.searchParams.get('code_challenge')).toBe('challenge-abc');
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    expect(url.searchParams.get('state')).toBe('state-xyz');
    expect(url.searchParams.get('scope')).toBe('read write');
    expect(url.searchParams.get('resource')).toBe('https://api.example.com');
  });

  it('omits optional parameters that are not set', async () => {
    const { buildAuthorizeUrl } = await import('./pkce.js');
    const url = new URL(
      buildAuthorizeUrl('https://auth.example.com/authorize', {
        clientId: 'cli-tool',
        redirectUri: 'http://localhost:8765/callback',
        codeChallenge: 'challenge-abc',
      }),
    );
    expect(url.searchParams.has('state')).toBe(false);
    expect(url.searchParams.has('scope')).toBe(false);
    expect(url.searchParams.has('resource')).toBe(false);
  });

  const authorizeParams = {
    clientId: 'sdk-client',
    redirectUri: 'https://app.example.com/callback',
    codeChallenge: 'challenge-abc',
  };

  it('row 3a: preserves unrelated parameters and replaces SDK parameters', async () => {
    const { buildAuthorizeUrl } = await import('./pkce.js');
    const url = new URL(buildAuthorizeUrl(
      'https://as.example/authorize?tenant=acme&client_id=x&client%5Fid=y',
      authorizeParams,
    ));
    expect(url.searchParams.getAll('tenant')).toEqual(['acme']);
    expect(url.searchParams.getAll('client_id')).toEqual(['sdk-client']);
    expect([...url.searchParams.keys()]).toHaveLength(new Set(url.searchParams.keys()).size);
  });

  it.each([
    [{ resources: ['a', 'b'] }, ['a', 'b']],
    [{ resource: 'b', resources: ['a', 'b', 'a'] }, ['b', 'a']],
    [{ resource: 'a' }, ['a']],
    [{ resources: [] }, ['https://old']],
    [{}, ['https://old']],
  ])('row 3b: merges SDK resources %j into the authorize URL', async (inputs, expected) => {
    const { buildAuthorizeUrl } = await import('./pkce.js');
    const url = new URL(buildAuthorizeUrl(
      'https://as.example/authorize?resource=https://old',
      { ...authorizeParams, ...inputs },
    ));
    expect(url.searchParams.getAll('resource')).toEqual(expected);
  });
});
