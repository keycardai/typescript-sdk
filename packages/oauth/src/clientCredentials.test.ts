import { jest } from '@jest/globals';
import { ClientCredentialsClient } from './clientCredentials.js';
import { OAuthError } from './errors.js';
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
      scope: 'read write',
    }),
    { status: 200, headers: { 'content-type': 'application/json' } },
  );
}

describe('ClientCredentialsClient.requestToken', () => {
  let originalFetch: typeof fetch;
  let fetchMock: jest.Mock;
  let tokenResponseFactory: () => Response;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
    tokenResponseFactory = mockTokenResponse;
    fetchMock = jest.fn(async (input: FetchInput, init?: FetchInit) => {
      const url = typeof input === 'string' ? input : (input as URL | Request).toString();
      if (url.includes('/.well-known/oauth-authorization-server')) {
        return mockMetadataResponse();
      }
      if (url === TOKEN_ENDPOINT) {
        return tokenResponseFactory();
      }
      throw new Error(`unexpected fetch: ${url}`);
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  function tokenCallBody(): URLSearchParams {
    const tokenCall = fetchMock.mock.calls.find(([url]) => url === TOKEN_ENDPOINT);
    expect(tokenCall).toBeDefined();
    const body = ((tokenCall![1] as RequestInit).body ?? '') as string;
    return new URLSearchParams(body);
  }

  function tokenCallHeaders(): Record<string, string> {
    const tokenCall = fetchMock.mock.calls.find(([url]) => url === TOKEN_ENDPOINT);
    expect(tokenCall).toBeDefined();
    return (tokenCall![1] as RequestInit).headers as Record<string, string>;
  }

  it('returns a TokenResponse and sends grant_type plus optional fields', async () => {
    const client = new ClientCredentialsClient(ISSUER);
    const token = await client.requestToken({
      resource: 'https://api.example.com',
      scope: 'read write',
      clientAssertion: 'assertion-jwt',
      clientAssertionType: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    });

    expect(token).toMatchObject({
      accessToken: 'issued-token',
      tokenType: 'Bearer',
      expiresIn: 3600,
      scope: ['read', 'write'],
    });

    const params = tokenCallBody();
    expect(params.get('grant_type')).toBe('client_credentials');
    expect(params.get('resource')).toBe('https://api.example.com');
    expect(params.get('scope')).toBe('read write');
    expect(params.get('client_assertion')).toBe('assertion-jwt');
    expect(params.get('client_assertion_type')).toBe(
      'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    );
  });

  it('sends only grant_type when called with no arguments', async () => {
    const client = new ClientCredentialsClient(ISSUER);
    await client.requestToken();

    const params = tokenCallBody();
    expect(params.get('grant_type')).toBe('client_credentials');
    expect([...params.keys()]).toEqual(['grant_type']);
  });

  it('omits optional fields from the wire body when not set', async () => {
    const client = new ClientCredentialsClient(ISSUER);
    await client.requestToken({ scope: 'read' });

    const params = tokenCallBody();
    expect(params.get('scope')).toBe('read');
    expect(params.has('resource')).toBe(false);
    expect(params.has('client_assertion')).toBe(false);
    expect(params.has('client_assertion_type')).toBe(false);
  });

  it('sends a Basic auth header when clientId and clientSecret are set', async () => {
    const client = new ClientCredentialsClient(ISSUER, { clientId: 'alice', clientSecret: 'shh' });
    await client.requestToken();

    const headers = tokenCallHeaders();
    expect(headers['Authorization']).toBe(`Basic ${btoa('alice:shh')}`);
  });

  it('resolves Basic auth from the credential by zoneId when a credential is provided', async () => {
    const credential = new ClientSecret({
      'zone-a': ['id-a', 'sec-a'],
      'zone-b': ['id-b', 'sec-b'],
    });
    const client = new ClientCredentialsClient(ISSUER, { credential });

    await client.requestToken({}, { zoneId: 'zone-b' });

    const headers = tokenCallHeaders();
    expect(headers['Authorization']).toBe(`Basic ${btoa('id-b:sec-b')}`);
  });

  it('throws an OAuthError on an RFC 6749 error response', async () => {
    tokenResponseFactory = () =>
      new Response(
        JSON.stringify({
          error: 'invalid_client',
          error_description: 'client authentication failed',
        }),
        { status: 401, headers: { 'content-type': 'application/json' } },
      );

    const client = new ClientCredentialsClient(ISSUER);
    await expect(client.requestToken()).rejects.toThrow(OAuthError);
  });

  it('throws a generic Error with the HTTP status on a non-JSON error response', async () => {
    tokenResponseFactory = () => new Response('upstream failure', { status: 502 });

    const client = new ClientCredentialsClient(ISSUER);
    await expect(client.requestToken()).rejects.toThrow(
      'Client credentials request failed (HTTP 502)',
    );
  });

  it('discovers the token endpoint once across multiple requests', async () => {
    const client = new ClientCredentialsClient(ISSUER);
    await client.requestToken();
    await client.requestToken();

    const metadataCalls = fetchMock.mock.calls.filter(([url]) =>
      String(url).includes('/.well-known/oauth-authorization-server'),
    );
    expect(metadataCalls).toHaveLength(1);
    const tokenCalls = fetchMock.mock.calls.filter(([url]) => url === TOKEN_ENDPOINT);
    expect(tokenCalls).toHaveLength(2);
  });

  it('throws when metadata does not advertise a token_endpoint', async () => {
    fetchMock.mockImplementation(async (input: FetchInput) => {
      const url = typeof input === 'string' ? input : (input as URL | Request).toString();
      if (url.includes('/.well-known/oauth-authorization-server')) {
        return new Response(JSON.stringify({ issuer: ISSUER }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      throw new Error(`unexpected fetch: ${url}`);
    });

    const client = new ClientCredentialsClient(ISSUER);
    await expect(client.requestToken()).rejects.toThrow(/does not advertise a token_endpoint/);
  });
});
