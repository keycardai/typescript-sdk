import { jest } from '@jest/globals';
import { fetchUserInfo } from './userinfo.js';
import { fetchAuthorizationServerMetadata } from './discovery.js';
import { HTTPError, InvalidTokenError, OAuthError } from './errors.js';

const ISSUER = 'https://auth.example.com';
const USERINFO_ENDPOINT = `${ISSUER}/userinfo`;
const ACCESS_TOKEN = 'access-token-123';

const METADATA = { issuer: ISSUER, userinfo_endpoint: USERINFO_ENDPOINT };

type FetchCall = { url: string; init?: RequestInit };

function mockFetch(responder: (url: string) => Response): FetchCall[] {
  const calls: FetchCall[] = [];
  globalThis.fetch = jest.fn(async (input: unknown, init?: unknown) => {
    const url = String(input);
    calls.push({ url, init: init as RequestInit | undefined });
    return responder(url);
  }) as unknown as typeof fetch;
  return calls;
}

function jsonResponse(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
}

describe('fetchUserInfo', () => {
  let originalFetch: typeof fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('sends the bearer token to the discovered userinfo_endpoint and returns typed claims', async () => {
    const calls = mockFetch((url) =>
      url.includes('.well-known')
        ? jsonResponse(200, METADATA)
        : jsonResponse(200, { sub: 'user-1', email: 'user@example.com', groups: ['admins'] }),
    );

    const user = await fetchUserInfo(ISSUER, ACCESS_TOKEN);

    expect(calls[0].url).toContain('/.well-known/oauth-authorization-server');
    expect(calls[1].url).toBe(USERINFO_ENDPOINT);
    expect(calls[1].init?.method).toBe('GET');
    const headers = calls[1].init?.headers as Record<string, string>;
    expect(headers['Authorization']).toBe(`Bearer ${ACCESS_TOKEN}`);
    expect(headers['Accept']).toBe('application/json');
    expect(user.sub).toBe('user-1');
    expect(user.claims.email).toBe('user@example.com');
  });

  it('preserves unknown claims beyond the common set', async () => {
    mockFetch(() => jsonResponse(200, { sub: 'user-1', 'urn:custom:tier': 'gold' }));

    const user = await fetchUserInfo(ISSUER, ACCESS_TOKEN, { metadata: METADATA });

    expect(user.claims).toEqual({ sub: 'user-1', 'urn:custom:tier': 'gold' });
  });

  it('skips discovery when pre-discovered metadata is supplied', async () => {
    const calls = mockFetch(() => jsonResponse(200, { sub: 'user-1' }));

    await fetchUserInfo(ISSUER, ACCESS_TOKEN, { metadata: METADATA });

    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe(USERINFO_ENDPOINT);
  });

  it('fails before any request when the metadata has no userinfo_endpoint', async () => {
    const calls = mockFetch(() => jsonResponse(200, { sub: 'user-1' }));

    await expect(
      fetchUserInfo(ISSUER, ACCESS_TOKEN, { metadata: { issuer: ISSUER } }),
    ).rejects.toThrow(/does not advertise a userinfo_endpoint/);
    expect(calls).toHaveLength(0);
  });

  it('rejects a response without sub', async () => {
    mockFetch(() => jsonResponse(200, { email: 'user@example.com' }));

    await expect(
      fetchUserInfo(ISSUER, ACCESS_TOKEN, { metadata: METADATA }),
    ).rejects.toMatchObject({ errorCode: 'invalid_response' });
  });

  it('maps a 401 invalid_token challenge to a typed authorization error', async () => {
    mockFetch(() =>
      new Response('', {
        status: 401,
        headers: { 'www-authenticate': 'Bearer error="invalid_token"' },
      }),
    );

    const error = await fetchUserInfo(ISSUER, ACCESS_TOKEN, { metadata: METADATA })
      .catch((e: unknown) => e);

    expect(error).toBeInstanceOf(InvalidTokenError);
    expect(error).toMatchObject({ errorCode: 'invalid_token' });
  });

  it('rejects a signed application/jwt response', async () => {
    mockFetch(() =>
      new Response('a.b.c', { status: 200, headers: { 'content-type': 'application/jwt' } }),
    );

    await expect(
      fetchUserInfo(ISSUER, ACCESS_TOKEN, { metadata: METADATA }),
    ).rejects.toThrow(/application\/jwt/);
  });

  it('rejects a non-JSON body', async () => {
    mockFetch(() => new Response('not json', { status: 200, headers: { 'content-type': 'application/json' } }));

    await expect(
      fetchUserInfo(ISSUER, ACCESS_TOKEN, { metadata: METADATA }),
    ).rejects.toBeInstanceOf(OAuthError);
  });

  it('throws HTTPError on a non-401 error status', async () => {
    mockFetch(() => jsonResponse(503, {}));

    await expect(
      fetchUserInfo(ISSUER, ACCESS_TOKEN, { metadata: METADATA }),
    ).rejects.toBeInstanceOf(HTTPError);
  });
});

describe('OIDC discovery fields', () => {
  let originalFetch: typeof fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('surfaces the typed OIDC fields from discovery', async () => {
    globalThis.fetch = jest.fn(async () =>
      jsonResponse(200, {
        issuer: ISSUER,
        userinfo_endpoint: USERINFO_ENDPOINT,
        end_session_endpoint: `${ISSUER}/logout`,
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256'],
        claims_supported: ['sub', 'email'],
        scopes_supported: ['openid', 'email'],
        code_challenge_methods_supported: ['S256'],
      }),
    ) as unknown as typeof fetch;

    const metadata = await fetchAuthorizationServerMetadata(ISSUER);

    expect(metadata.userinfo_endpoint).toBe(USERINFO_ENDPOINT);
    expect(metadata.end_session_endpoint).toBe(`${ISSUER}/logout`);
    expect(metadata.subject_types_supported).toEqual(['public']);
    expect(metadata.id_token_signing_alg_values_supported).toEqual(['RS256']);
    expect(metadata.claims_supported).toEqual(['sub', 'email']);
    expect(metadata.scopes_supported).toEqual(['openid', 'email']);
    expect(metadata.code_challenge_methods_supported).toEqual(['S256']);
  });

  it('leaves the OIDC fields undefined when absent', async () => {
    globalThis.fetch = jest.fn(async () =>
      jsonResponse(200, { issuer: ISSUER }),
    ) as unknown as typeof fetch;

    const metadata = await fetchAuthorizationServerMetadata(ISSUER);

    expect(metadata.userinfo_endpoint).toBeUndefined();
    expect(metadata.claims_supported).toBeUndefined();
  });
});
