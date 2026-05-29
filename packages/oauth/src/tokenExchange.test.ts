import { jest } from '@jest/globals';
import { TokenExchangeClient, TokenType } from './tokenExchange.js';
import { OAuthError } from './errors.js';
import { ClientSecret } from './server/clientSecret.js';

const ISSUER = 'https://auth.example.com';
const TOKEN_ENDPOINT = 'https://auth.example.com/token';

type FetchInput = Parameters<typeof fetch>[0];
type FetchInit = Parameters<typeof fetch>[1];

function metadataResponse(): Response {
  return new Response(
    JSON.stringify({ issuer: ISSUER, token_endpoint: TOKEN_ENDPOINT }),
    { status: 200, headers: { 'content-type': 'application/json' } },
  );
}

function actorTokenResponse(): Response {
  return new Response(
    JSON.stringify({
      access_token: 'actor-access-token',
      token_type: 'Bearer',
      expires_in: 3600,
    }),
    { status: 200, headers: { 'content-type': 'application/json' } },
  );
}

function issuedTokenResponse(scope?: string): Response {
  const body: Record<string, unknown> = {
    access_token: 'issued-token',
    token_type: 'Bearer',
    expires_in: 3600,
  };
  if (scope) body.scope = scope;
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}

function oauthErrorResponse(error: string): Response {
  return new Response(JSON.stringify({ error }), {
    status: 400,
    headers: { 'content-type': 'application/json' },
  });
}

/**
 * Build a fetch mock that returns the metadata document on discovery and then
 * walks through `tokenResponses` for each subsequent call to the token endpoint.
 */
function makeFetchMock(tokenResponses: Response[]): jest.Mock {
  let i = 0;
  return jest.fn(async (input: FetchInput) => {
    const url = typeof input === 'string' ? input : (input as URL | Request).toString();
    if (url.includes('/.well-known/oauth-authorization-server')) {
      return metadataResponse();
    }
    if (url === TOKEN_ENDPOINT) {
      const next = tokenResponses[i++];
      if (!next) throw new Error(`unexpected token-endpoint call #${i}`);
      return next;
    }
    throw new Error(`unexpected fetch: ${url}`);
  });
}

function tokenCalls(mock: jest.Mock): URLSearchParams[] {
  return mock.mock.calls
    .filter(([url]) => url === TOKEN_ENDPOINT)
    .map(([, init]) => new URLSearchParams(((init as RequestInit).body ?? '') as string));
}

describe('TokenExchangeClient.impersonate', () => {
  let originalFetch: typeof fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });
  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('mints an actor token via client_credentials then exchanges it', async () => {
    const fetchMock = makeFetchMock([actorTokenResponse(), issuedTokenResponse('read:mail')]);
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const client = new TokenExchangeClient(ISSUER, { clientId: 'app', clientSecret: 'shh' });
    const response = await client.impersonate({
      userIdentifier: 'alice@example.com',
      resource: 'https://api.example.com',
      scopes: ['read:mail'],
    });

    expect(response.accessToken).toBe('issued-token');

    const [cc, exchange] = tokenCalls(fetchMock);
    expect(cc.get('grant_type')).toBe('client_credentials');

    expect(exchange.get('grant_type')).toBe('urn:ietf:params:oauth:grant-type:token-exchange');
    expect(exchange.get('subject_token_type')).toBe(TokenType.SUBSTITUTE_USER);
    expect(exchange.get('actor_token')).toBe('actor-access-token');
    expect(exchange.get('actor_token_type')).toBe(TokenType.ACCESS_TOKEN);
    expect(exchange.get('resource')).toBe('https://api.example.com');
    expect(exchange.get('scope')).toBe('read:mail');
  });

  it('encodes multiple scopes as a space-separated value', async () => {
    const fetchMock = makeFetchMock([actorTokenResponse(), issuedTokenResponse()]);
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const client = new TokenExchangeClient(ISSUER, { clientId: 'app', clientSecret: 'shh' });
    await client.impersonate({
      userIdentifier: 'alice@example.com',
      scopes: ['read:mail', 'read:calendar'],
    });

    const [, exchange] = tokenCalls(fetchMock);
    expect(exchange.get('scope')).toBe('read:mail read:calendar');
  });

  it('omits resource when not provided', async () => {
    const fetchMock = makeFetchMock([actorTokenResponse(), issuedTokenResponse()]);
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const client = new TokenExchangeClient(ISSUER, { clientId: 'app', clientSecret: 'shh' });
    await client.impersonate({ userIdentifier: 'alice@example.com' });

    const [, exchange] = tokenCalls(fetchMock);
    expect(exchange.has('resource')).toBe(false);
  });

  it('omits scope when scopes is not provided', async () => {
    const fetchMock = makeFetchMock([actorTokenResponse(), issuedTokenResponse()]);
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const client = new TokenExchangeClient(ISSUER, { clientId: 'app', clientSecret: 'shh' });
    await client.impersonate({
      userIdentifier: 'alice@example.com',
      resource: 'https://api.example.com',
    });

    const [, exchange] = tokenCalls(fetchMock);
    expect(exchange.has('scope')).toBe(false);
  });

  it('surfaces invalid_grant when the user is unknown', async () => {
    const fetchMock = makeFetchMock([actorTokenResponse(), oauthErrorResponse('invalid_grant')]);
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const client = new TokenExchangeClient(ISSUER, { clientId: 'app', clientSecret: 'shh' });
    await expect(
      client.impersonate({ userIdentifier: 'ghost@example.com' }),
    ).rejects.toBeInstanceOf(OAuthError);
  });

  it('surfaces unauthorized_client when the caller is not permitted', async () => {
    const fetchMock = makeFetchMock([actorTokenResponse(), oauthErrorResponse('unauthorized_client')]);
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const client = new TokenExchangeClient(ISSUER, { clientId: 'app', clientSecret: 'shh' });
    await expect(
      client.impersonate({ userIdentifier: 'alice@example.com' }),
    ).rejects.toMatchObject({ errorCode: 'unauthorized_client' });
  });

  it('throws on missing userIdentifier without calling the network', async () => {
    const fetchMock = makeFetchMock([]);
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const client = new TokenExchangeClient(ISSUER, { clientId: 'app', clientSecret: 'shh' });
    await expect(
      client.impersonate({ userIdentifier: '' }),
    ).rejects.toThrow(/userIdentifier is required/);
    expect(tokenCalls(fetchMock)).toHaveLength(0);
  });

  it('routes the Basic auth header by zoneId when a multi-zone credential is provided', async () => {
    const fetchMock = makeFetchMock([actorTokenResponse(), issuedTokenResponse()]);
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const credential = new ClientSecret({
      'zone-a': ['id-a', 'sec-a'],
      'zone-b': ['id-b', 'sec-b'],
    });
    const client = new TokenExchangeClient(ISSUER, { credential });
    await client.impersonate({
      userIdentifier: 'alice@example.com',
      zoneId: 'zone-b',
    });

    const tokenFetchCalls = fetchMock.mock.calls.filter(([url]) => url === TOKEN_ENDPOINT);
    const expected = `Basic ${btoa('id-b:sec-b')}`;
    for (const [, init] of tokenFetchCalls) {
      const headers = (init as RequestInit).headers as Record<string, string>;
      expect(headers['Authorization']).toBe(expected);
    }
  });
});

describe('TokenExchangeClient.exchangeToken', () => {
  let originalFetch: typeof fetch;
  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });
  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('preserves the legacy clientId/clientSecret authorization shape', async () => {
    const fetchMock = makeFetchMock([issuedTokenResponse()]);
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const client = new TokenExchangeClient(ISSUER, { clientId: 'alice', clientSecret: 'shh' });
    await client.exchangeToken({
      subjectToken: 'subject',
      resource: 'https://api.example.com',
    });

    const tokenCall = fetchMock.mock.calls.find(([url]) => url === TOKEN_ENDPOINT);
    const headers = (tokenCall![1] as RequestInit).headers as Record<string, string>;
    expect(headers['Authorization']).toBe(`Basic ${btoa('alice:shh')}`);
  });
});
