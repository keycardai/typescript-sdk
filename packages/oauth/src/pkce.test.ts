import { jest } from '@jest/globals';
import {
  generateCodeVerifier,
  generateCodeChallenge,
  generatePkcePair,
  exchangeAuthorizationCode,
  authenticate,
} from './pkce.js';
import { OAuthError } from './errors.js';

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
  it('returns a 43-character base64url string with no padding', () => {
    const verifier = generateCodeVerifier();
    expect(verifier).toHaveLength(43);
    expect(verifier).toMatch(/^[A-Za-z0-9\-_]+$/);
    expect(verifier).not.toContain('=');
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
    ).rejects.toThrow(/does not advertise a token_endpoint/);
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

    const authPromise = authenticate(ISSUER, {
      clientId: 'my-client',
      port: testPort,
      timeoutMs: 5000,
    });

    // Give the loopback server time to start
    await new Promise((r) => setTimeout(r, 80));

    // Simulate the browser being redirected back with an authorization code.
    // Use the real fetch (saved before mocking) so it actually hits the loopback server.
    await originalFetch(`http://localhost:${testPort}/callback?code=auth-code-xyz`);

    const result = await authPromise;
    expect(result.accessToken).toBe('pkce-tok');
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
      authenticate(ISSUER, { clientId: 'my-client', port: testPort, timeoutMs: 200 }),
    ).rejects.toThrow(/timed out/);
  }, 3000);
});
