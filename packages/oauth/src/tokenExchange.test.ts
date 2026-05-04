import { jest } from '@jest/globals';
import { TokenExchangeClient, TokenType } from './tokenExchange.js';
import { ClientSecret } from './server/clientSecret.js';

const ISSUER = 'https://auth.example.com';
const TOKEN_ENDPOINT = 'https://auth.example.com/token';

type FetchInput = Parameters<typeof fetch>[0];
type FetchInit = Parameters<typeof fetch>[1];

function mockMetadataResponse(): Response {
  return new Response(
    JSON.stringify({
      issuer: ISSUER,
      token_endpoint: TOKEN_ENDPOINT,
    }),
    { status: 200, headers: { 'content-type': 'application/json' } },
  );
}

function mockTokenResponse(): Response {
  return new Response(
    JSON.stringify({
      access_token: 'issued-token',
      token_type: 'Bearer',
      expires_in: 3600,
    }),
    { status: 200, headers: { 'content-type': 'application/json' } },
  );
}

describe('TokenExchangeClient.impersonate', () => {
  let originalFetch: typeof fetch;
  let fetchMock: jest.Mock;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
    fetchMock = jest.fn(async (input: FetchInput, init?: FetchInit) => {
      const url = typeof input === 'string' ? input : (input as URL | Request).toString();
      if (url.includes('/.well-known/oauth-authorization-server')) {
        return mockMetadataResponse();
      }
      if (url === TOKEN_ENDPOINT) {
        return mockTokenResponse();
      }
      throw new Error(`unexpected fetch: ${url}`);
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('posts the substitute-user URN as subject_token_type', async () => {
    const client = new TokenExchangeClient(ISSUER, { clientId: 'app', clientSecret: 'shh' });
    await client.impersonate({
      userIdentifier: 'user@example.com',
      resource: 'https://api.example.com',
    });

    const tokenCall = fetchMock.mock.calls.find(([url]) => url === TOKEN_ENDPOINT);
    expect(tokenCall).toBeDefined();
    const body = ((tokenCall![1] as RequestInit).body ?? '') as string;
    const params = new URLSearchParams(body);
    expect(params.get('subject_token_type')).toBe(TokenType.SUBSTITUTE_USER);
    expect(params.get('resource')).toBe('https://api.example.com');
    expect(params.get('grant_type')).toBe('urn:ietf:params:oauth:grant-type:token-exchange');
  });

  it('routes the Basic auth header by zoneId when a multi-zone credential is provided', async () => {
    const credential = new ClientSecret({
      'zone-a': ['id-a', 'sec-a'],
      'zone-b': ['id-b', 'sec-b'],
    });
    const client = new TokenExchangeClient(ISSUER, { credential });

    await client.impersonate({
      userIdentifier: 'user@example.com',
      resource: 'https://api.example.com',
      zoneId: 'zone-b',
    });

    const tokenCall = fetchMock.mock.calls.find(([url]) => url === TOKEN_ENDPOINT);
    const headers = (tokenCall![1] as RequestInit).headers as Record<string, string>;
    const expected = `Basic ${btoa('id-b:sec-b')}`;
    expect(headers['Authorization']).toBe(expected);
  });

  it('preserves the legacy clientId/clientSecret authorization shape', async () => {
    const client = new TokenExchangeClient(ISSUER, { clientId: 'alice', clientSecret: 'shh' });

    await client.exchangeToken({
      subjectToken: 'subject',
      resource: 'https://api.example.com',
    });

    const tokenCall = fetchMock.mock.calls.find(([url]) => url === TOKEN_ENDPOINT);
    const headers = (tokenCall![1] as RequestInit).headers as Record<string, string>;
    expect(headers['Authorization']).toBe(`Basic ${btoa('alice:shh')}`);
  });

  it('throws on missing userIdentifier', async () => {
    const client = new TokenExchangeClient(ISSUER, { clientId: 'app', clientSecret: 'shh' });
    await expect(
      client.impersonate({ userIdentifier: '', resource: 'https://api.example.com' }),
    ).rejects.toThrow(/userIdentifier is required/);
  });
});
