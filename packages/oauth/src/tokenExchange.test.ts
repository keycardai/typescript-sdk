import { jest } from '@jest/globals';
import { TokenExchangeClient, TokenType } from './tokenExchange.js';
import { ClientSecret } from './server/clientSecret.js';
import {
  WorkloadIdentity,
  WorkloadIdentityConfigurationError,
  WorkloadIdentityRuntimeError,
} from './server/workloadIdentity.js';
import { ConfigurationError, HTTPError, OAuthError } from './errors.js';
import { buildSubstituteUserToken } from './jwt/substituteUser.js';
import type { ApplicationCredential } from './credentials.js';
import type { TokenExchangeRequest } from './tokenExchange.js';

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

/** A token endpoint that never answers: settles only when the request is aborted. */
function hangUntilAborted(init?: FetchInit): Promise<Response> {
  return new Promise((_, reject) => {
    init?.signal?.addEventListener('abort', () => reject(init.signal!.reason));
  });
}

describe('TokenExchangeClient', () => {
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

  it.each([
    ['6a', 'custom_denial'],
    ['6b', undefined],
  ])('row %s: preserves the optional denial reason and separate description', async (_row, reason) => {
    const payload = { error: 'access_denied', error_description: 'Denied', reason };
    fetchMock.mockImplementation(async (input: FetchInput) =>
      input === TOKEN_ENDPOINT ? Response.json(payload, { status: 400 }) : mockMetadataResponse(),
    );
    const client = new TokenExchangeClient(ISSUER);

    await expect(client.exchangeToken({ subjectToken: 'subject' })).rejects.toMatchObject({
      errorCode: 'access_denied', errorDescription: 'Denied', reason, retryable: false,
    });
  });

  it.each([
    ['static credentials', { clientId: 'configured', clientSecret: 'secret' }],
    ['ClientSecret', { credential: new ClientSecret('configured', 'secret') }],
  ] as const)('row 4f: rejects a request clientId with %s before discovery', async (_name, options) => {
    const actor = jest.fn(() => 'actor-jwt');
    const client = new TokenExchangeClient(ISSUER, { ...options, actor });

    await expect(client.exchangeToken({ subjectToken: 'subject', clientId: 'request-id' }))
      .rejects.toThrow(ConfigurationError);
    expect(fetchMock).not.toHaveBeenCalled();
    expect(actor).not.toHaveBeenCalled();
  });

  it('row 4f: resolves the client issuer for a multi-zone ClientSecret without a per-call issuer', async () => {
    const credential = new ClientSecret({
      [ISSUER]: ['configured', 'secret'],
      'https://zone-b.keycard.cloud': ['id-b', 'sec-b'],
    });
    const client = new TokenExchangeClient(ISSUER, { credential });

    await expect(client.exchangeToken({ subjectToken: 'subject', clientId: 'request-id' }))
      .rejects.toThrow(ConfigurationError);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([undefined, 'request-id'])(
    'row 4g: an explicit assertion suppresses Basic with clientId %s',
    async (clientId) => {
      const assertionType = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
      const credential = new ClientSecret('configured', 'secret');
      const prepare = jest.spyOn(credential, 'prepareTokenExchangeRequest');
      const client = new TokenExchangeClient(ISSUER, { credential });

      await client.exchangeToken({
        subjectToken: 'subject',
        clientAssertion: 'assertion',
        clientAssertionType: assertionType,
        clientId,
      });

      const tokenCall = fetchMock.mock.calls.find(([url]) => url === TOKEN_ENDPOINT);
      const { body, headers } = tokenCall![1] as RequestInit;
      const params = new URLSearchParams(body as string);
      expect(params.get('client_assertion')).toBe('assertion');
      expect(params.get('client_assertion_type')).toBe(assertionType);
      expect(params.get('client_id')).toBe(clientId ?? null);
      expect(new Headers(headers).has('Authorization')).toBe(false);
      expect(prepare).not.toHaveBeenCalled();
    },
  );

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

  it('serializes clientId as the client_id form parameter', async () => {
    const client = new TokenExchangeClient(ISSUER, { clientId: 'app', clientSecret: 'shh' });
    await client.exchangeToken({
      subjectToken: 'subject',
      resource: 'https://api.example.com',
      clientAssertion: 'platform-jwt',
      clientAssertionType: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      clientId: 'acr_123',
    });

    const tokenCall = fetchMock.mock.calls.find(([url]) => url === TOKEN_ENDPOINT);
    const params = new URLSearchParams(((tokenCall![1] as RequestInit).body ?? '') as string);
    expect(params.get('client_id')).toBe('acr_123');
    expect(params.get('client_assertion')).toBe('platform-jwt');
  });

  it('routes the Basic auth header by issuer when a multi-zone credential is provided', async () => {
    const credential = new ClientSecret({
      'https://zone-a.keycard.cloud': ['id-a', 'sec-a'],
      'https://zone-b.keycard.cloud': ['id-b', 'sec-b'],
    });
    const client = new TokenExchangeClient(ISSUER, { credential });

    await client.impersonate({
      userIdentifier: 'user@example.com',
      resource: 'https://api.example.com',
      issuer: 'https://zone-b.keycard.cloud',
    });

    const tokenCall = fetchMock.mock.calls.find(([url]) => url === TOKEN_ENDPOINT);
    const headers = (tokenCall![1] as RequestInit).headers as Record<string, string>;
    const expected = `Basic ${btoa('id-b:sec-b')}`;
    expect(headers['Authorization']).toBe(expected);
  });

  it('routes exchangeToken Basic auth by per-call issuer, including a trailing slash', async () => {
    const credential = new ClientSecret({
      'https://zone-a.keycard.cloud': ['id-a', 'sec-a'],
      'https://zone-b.keycard.cloud': ['id-b', 'sec-b'],
    });
    const client = new TokenExchangeClient(ISSUER, { credential });

    await client.exchangeToken(
      { subjectToken: 'subject', resource: 'https://api.example.com' },
      { issuer: 'https://zone-a.keycard.cloud/' },
    );

    const tokenCall = fetchMock.mock.calls.find(([url]) => url === TOKEN_ENDPOINT);
    const headers = (tokenCall![1] as RequestInit).headers as Record<string, string>;
    expect(headers['Authorization']).toBe(`Basic ${btoa('id-a:sec-a')}`);
  });

  it('row 3: exchangeToken uses the client issuer for multi-zone Basic auth by default', async () => {
    const credential = new ClientSecret({
      [ISSUER]: ['default-id', 'default-secret'],
      'https://other.example.com': ['other-id', 'other-secret'],
    });
    const client = new TokenExchangeClient(ISSUER, { credential });

    await client.exchangeToken({ subjectToken: 'subject' });

    const tokenCall = fetchMock.mock.calls.find(([url]) => url === TOKEN_ENDPOINT);
    const headers = (tokenCall![1] as RequestInit).headers as Record<string, string>;
    expect(headers['Authorization']).toBe(`Basic ${btoa('default-id:default-secret')}`);
  });

  it('sends no Authorization header when the per-call issuer has no credential entry', async () => {
    const credential = new ClientSecret({
      'https://zone-a.keycard.cloud': ['id-a', 'sec-a'],
    });
    const client = new TokenExchangeClient(ISSUER, { credential });

    await client.exchangeToken(
      { subjectToken: 'subject', resource: 'https://api.example.com' },
      { issuer: 'https://zone-x.keycard.cloud' },
    );

    const tokenCall = fetchMock.mock.calls.find(([url]) => url === TOKEN_ENDPOINT);
    const headers = (tokenCall![1] as RequestInit).headers as Record<string, string>;
    expect(headers['Authorization']).toBeUndefined();
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

  it('authenticates with the credential\'s client assertion, not Basic auth', async () => {
    const credential = new WorkloadIdentity(async () => 'workload-oidc-jwt');
    const client = new TokenExchangeClient(ISSUER, { credential });

    await client.impersonate({
      userIdentifier: 'user@example.com',
      resource: 'https://api.example.com',
      scope: 'calendar.read',
    });

    const tokenCall = fetchMock.mock.calls.find(([url]) => url === TOKEN_ENDPOINT);
    const headers = (tokenCall![1] as RequestInit).headers as Record<string, string>;
    expect(headers['Authorization']).toBeUndefined();
    const params = new URLSearchParams(((tokenCall![1] as RequestInit).body ?? '') as string);
    expect(params.get('client_assertion')).toBe('workload-oidc-jwt');
    expect(params.get('client_assertion_type')).toBe(
      'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    );
    expect(params.get('client_id')).toBeNull();
    expect(params.get('subject_token_type')).toBe(TokenType.SUBSTITUTE_USER);
    expect(params.get('subject_token')).toBe(buildSubstituteUserToken('user@example.com'));
    expect(params.get('resource')).toBe('https://api.example.com');
    expect(params.get('scope')).toBe('calendar.read');
    expect(params.has('actor_token')).toBe(false);
    expect(params.has('audience')).toBe(false);
  });

  it('sends the credential\'s clientId as client_id alongside the assertion', async () => {
    const credential = new WorkloadIdentity(async () => 'workload-oidc-jwt', { clientId: 'acr_123' });
    const client = new TokenExchangeClient(ISSUER, { credential });

    await client.impersonate({
      userIdentifier: 'user@example.com',
      resource: 'https://api.example.com',
    });

    const tokenCall = fetchMock.mock.calls.find(([url]) => url === TOKEN_ENDPOINT);
    const params = new URLSearchParams(((tokenCall![1] as RequestInit).body ?? '') as string);
    expect(params.get('client_id')).toBe('acr_123');
    expect(params.get('client_assertion')).toBe('workload-oidc-jwt');
  });

  it('keeps Basic auth and sends no assertion for a ClientSecret credential', async () => {
    const credential = new ClientSecret('app', 'shh');
    const client = new TokenExchangeClient(ISSUER, { credential });

    await client.impersonate({
      userIdentifier: 'user@example.com',
      resource: 'https://api.example.com',
    });

    const tokenCall = fetchMock.mock.calls.find(([url]) => url === TOKEN_ENDPOINT);
    const headers = (tokenCall![1] as RequestInit).headers as Record<string, string>;
    expect(headers['Authorization']).toBe(`Basic ${btoa('app:shh')}`);
    const params = new URLSearchParams(((tokenCall![1] as RequestInit).body ?? '') as string);
    expect(params.has('client_assertion')).toBe(false);
    expect(params.has('client_assertion_type')).toBe(false);
    expect(params.has('client_id')).toBe(false);
    expect(params.get('subject_token_type')).toBe(TokenType.SUBSTITUTE_USER);
  });

  it('passes the resolved token endpoint and per-call issuer to the credential', async () => {
    const prepare = jest.fn(
      async (subjectToken: string, resource: string): Promise<TokenExchangeRequest> => ({
        subjectToken,
        resource,
        subjectTokenType: TokenType.ACCESS_TOKEN,
        clientAssertion: 'prepared-assertion',
        clientAssertionType: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        actorToken: 'prepared-actor',
        actorTokenType: 'urn:ietf:params:oauth:token-type:jwt',
      }),
    );
    const getAuth = jest.fn((_issuer?: string) => null);
    const credential: ApplicationCredential = { getAuth, prepareTokenExchangeRequest: prepare };
    const client = new TokenExchangeClient(ISSUER, { credential });

    await client.impersonate({
      userIdentifier: 'user@example.com',
      resource: 'https://api.example.com',
      issuer: 'https://zone-b.keycard.cloud',
    });

    expect(prepare).toHaveBeenCalledWith(
      buildSubstituteUserToken('user@example.com'),
      'https://api.example.com',
      { tokenEndpoint: TOKEN_ENDPOINT, issuer: 'https://zone-b.keycard.cloud' },
    );
    expect(getAuth).not.toHaveBeenCalled();
    const tokenCall = fetchMock.mock.calls.find(([url]) => url === TOKEN_ENDPOINT);
    const params = new URLSearchParams(((tokenCall![1] as RequestInit).body ?? '') as string);
    expect(params.get('client_assertion')).toBe('prepared-assertion');
    expect(params.get('subject_token_type')).toBe(TokenType.SUBSTITUTE_USER);
    expect(params.has('actor_token')).toBe(false);
    expect(params.has('actor_token_type')).toBe(false);
  });

  it('row 4b: exchangeToken sends credential authentication and keeps caller fields', async () => {
    const credential = new WorkloadIdentity(async () => 'workload-oidc-jwt', { clientId: 'acr_123' });
    const client = new TokenExchangeClient(ISSUER, { credential });

    await client.exchangeToken({
      subjectToken: 'subject',
      resource: 'https://api.example.com',
      scope: 'calendar.read',
      audience: 'aud-1',
    });

    const tokenCall = fetchMock.mock.calls.find(([url]) => url === TOKEN_ENDPOINT);
    const headers = (tokenCall![1] as RequestInit).headers as Record<string, string>;
    expect(headers['Authorization']).toBeUndefined();
    const params = new URLSearchParams(((tokenCall![1] as RequestInit).body ?? '') as string);
    expect(params.get('client_assertion')).toBe('workload-oidc-jwt');
    expect(params.get('client_assertion_type')).toBe(
      'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    );
    expect(params.get('client_id')).toBe('acr_123');
    expect(params.get('subject_token')).toBe('subject');
    expect(params.get('subject_token_type')).toBe(TokenType.ACCESS_TOKEN);
    expect(params.get('resource')).toBe('https://api.example.com');
    expect(params.get('scope')).toBe('calendar.read');
    expect(params.get('audience')).toBe('aud-1');
  });

  it.each([
    ['credential-client', 'https://zone-b.keycard.cloud'],
    [undefined, undefined],
  ])('row 4e: exchangeToken uses only the prepared client ID (%s)', async (preparedId, issuer) => {
    const prepare = jest.fn(
      async (_subjectToken: string, _resource: string): Promise<TokenExchangeRequest> => ({
        subjectToken: 'credential-subject',
        resource: 'https://credential.example.com',
        subjectTokenType: TokenType.ACCESS_TOKEN,
        clientAssertion: 'prepared-assertion',
        clientAssertionType: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        clientId: preparedId,
      }),
    );
    const credential: ApplicationCredential = { getAuth: () => null, prepareTokenExchangeRequest: prepare };
    const client = new TokenExchangeClient(ISSUER, { credential });

    await client.exchangeToken(
      {
        subjectToken: 'subject',
        subjectTokenType: TokenType.SUBSTITUTE_USER,
        resource: 'https://api.example.com',
        clientId: 'caller-client',
      },
      { issuer },
    );

    expect(prepare).toHaveBeenCalledWith('subject', 'https://api.example.com', {
      tokenEndpoint: TOKEN_ENDPOINT,
      issuer: issuer ?? ISSUER,
    });
    const tokenCall = fetchMock.mock.calls.find(([url]) => url === TOKEN_ENDPOINT);
    const params = new URLSearchParams(((tokenCall![1] as RequestInit).body ?? '') as string);
    expect(params.get('client_assertion')).toBe('prepared-assertion');
    expect(params.get('client_id')).toBe(preparedId ?? null);
    expect(params.get('subject_token')).toBe('subject');
    expect(params.get('subject_token_type')).toBe(TokenType.SUBSTITUTE_USER);
    expect(params.get('resource')).toBe('https://api.example.com');
  });

  it('row 4c: exchangeToken sends caller authentication without preparing', async () => {
    const prepare = jest.fn(async (): Promise<TokenExchangeRequest> => {
      throw new Error('prepareTokenExchangeRequest should not be called');
    });
    const credential: ApplicationCredential = { getAuth: () => null, prepareTokenExchangeRequest: prepare };
    const client = new TokenExchangeClient(ISSUER, { credential });

    await client.exchangeToken({
      subjectToken: 'subject',
      clientAssertion: 'caller-assertion',
      clientAssertionType: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      clientId: 'caller-client',
    });

    expect(prepare).not.toHaveBeenCalled();
    const tokenCall = fetchMock.mock.calls.find(([url]) => url === TOKEN_ENDPOINT);
    const params = new URLSearchParams(((tokenCall![1] as RequestInit).body ?? '') as string);
    expect(params.get('client_assertion')).toBe('caller-assertion');
    expect(params.get('client_assertion_type')).toBe('urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
    expect(params.get('client_id')).toBe('caller-client');
    expect(((tokenCall![1] as RequestInit).headers as Record<string, string>)['Authorization']).toBeUndefined();
  });

  it('row 3: exchangeToken with a ClientSecret sends Basic auth and no assertion or client_id', async () => {
    const prepare = jest.fn(async (): Promise<TokenExchangeRequest> => {
      throw new Error('prepareTokenExchangeRequest should not be called');
    });
    const secret = new ClientSecret('app', 'shh');
    const credential: ApplicationCredential = {
      getAuth: (issuer?: string) => secret.getAuth(issuer),
      prepareTokenExchangeRequest: prepare,
    };
    const client = new TokenExchangeClient(ISSUER, { credential });

    await client.exchangeToken({ subjectToken: 'subject' });

    expect(prepare).not.toHaveBeenCalled();
    const tokenCall = fetchMock.mock.calls.find(([url]) => url === TOKEN_ENDPOINT);
    const headers = (tokenCall![1] as RequestInit).headers as Record<string, string>;
    expect(headers['Authorization']).toBe(`Basic ${btoa('app:shh')}`);
    const params = new URLSearchParams(((tokenCall![1] as RequestInit).body ?? '') as string);
    expect(params.has('client_assertion')).toBe(false);
    expect(params.has('client_id')).toBe(false);
  });

  it('row 4d: exchangeToken sends no token POST when the WorkloadIdentity token source fails', async () => {
    const credential = new WorkloadIdentity(async () => {
      throw new Error('metadata down');
    });
    const client = new TokenExchangeClient(ISSUER, { credential });

    await expect(client.exchangeToken({ subjectToken: 'subject' })).rejects.toThrow(
      'Error fetching identity token',
    );
    expect(fetchMock.mock.calls.find(([url]) => url === TOKEN_ENDPOINT)).toBeUndefined();
  });

  function tokenRequestBodies(): URLSearchParams[] {
    return fetchMock.mock.calls
      .filter(([url]) => url === TOKEN_ENDPOINT)
      .map(([, init]) => new URLSearchParams((init as RequestInit).body as string));
  }

  it.each([null, {}, { identityToken: 'not callable' }])(
    'rejects an invalid actor source at construction: %j',
    (actor) => {
      expect(() => new TokenExchangeClient(ISSUER, { actor: actor as never }))
        .toThrow(WorkloadIdentityConfigurationError);
      expect(fetchMock).not.toHaveBeenCalled();
    },
  );

  it('row 23: reads the current actor JWT once per exchange', async () => {
    const actor = {
      identityToken: jest.fn(async () => 'rotated-jwt').mockResolvedValueOnce('first-jwt'),
    };
    const client = new TokenExchangeClient(ISSUER, { actor, clientId: 'app', clientSecret: 'secret' });
    const request = { subjectToken: 'subject' };

    await client.exchangeToken(request);
    await client.exchangeToken(request);

    expect(tokenRequestBodies().map((body) => [body.get('actor_token'), body.get('actor_token_type')]))
      .toEqual([
        ['first-jwt', 'urn:ietf:params:oauth:token-type:jwt'],
        ['rotated-jwt', 'urn:ietf:params:oauth:token-type:jwt'],
      ]);
    expect(actor.identityToken).toHaveBeenCalledTimes(2);
    expect(request).toEqual({ subjectToken: 'subject' });
  });

  it('row 24: uses explicit actor fields without calling the source', async () => {
    const actor = jest.fn(() => 'source-jwt');
    const client = new TokenExchangeClient(ISSUER, { actor });
    const actorTokenType = 'urn:ietf:params:oauth:token-type:access_token';

    await client.exchangeToken({ subjectToken: 'subject', actorToken: 'explicit', actorTokenType });

    const [explicitBody] = tokenRequestBodies();
    expect(explicitBody.get('actor_token')).toBe('explicit');
    expect(explicitBody.get('actor_token_type')).toBe(actorTokenType);
    expect(actor).not.toHaveBeenCalled();

    await client.exchangeToken({ subjectToken: 'subject' });
    expect(tokenRequestBodies()[1].get('actor_token')).toBe('source-jwt');
    expect(actor).toHaveBeenCalledTimes(1);
  });

  it.each(['', null])('row 24: uses the source when the request actor token is %j', async (actorToken) => {
    const actor = jest.fn(() => 'source-jwt');
    const client = new TokenExchangeClient(ISSUER, { actor });

    await client.exchangeToken({
      subjectToken: 'subject',
      actorToken: actorToken as string,
      actorTokenType: 'urn:ietf:params:oauth:token-type:access_token',
    });

    const [body] = tokenRequestBodies();
    expect(body.get('actor_token')).toBe('source-jwt');
    expect(body.get('actor_token_type')).toBe('urn:ietf:params:oauth:token-type:jwt');
    expect(actor).toHaveBeenCalledTimes(1);
  });

  it('row 25: omits actor fields and skips the source on impersonation', async () => {
    const actor = jest.fn(async () => 'source-jwt');
    const client = new TokenExchangeClient(ISSUER, { actor, clientId: 'app', clientSecret: 'secret' });

    await client.impersonate({ userIdentifier: 'user@example.com', resource: 'https://api.example.com' });

    const [impersonationBody] = tokenRequestBodies();
    expect(impersonationBody.has('actor_token')).toBe(false);
    expect(impersonationBody.has('actor_token_type')).toBe(false);
    expect(actor).not.toHaveBeenCalled();

    await client.exchangeToken({ subjectToken: 'subject' });
    expect(tokenRequestBodies()[1].get('actor_token')).toBe('source-jwt');
    expect(actor).toHaveBeenCalledTimes(1);
  });

  it.each([
    ['configuration error', new WorkloadIdentityConfigurationError('source misconfigured')],
    ['runtime error', new WorkloadIdentityRuntimeError('source failed')],
  ])('row 26: passes the typed %s through without sending a request', async (_label, cause) => {
    const actor = { identityToken: jest.fn(async () => { throw cause; }) };
    const client = new TokenExchangeClient(ISSUER, { actor });

    await expect(client.exchangeToken({ subjectToken: 'subject' })).rejects.toBe(cause);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([
    ['plain error', new Error('source failed'), false],
    ['timeout', new DOMException('source timed out', 'TimeoutError'), true],
    ['5xx', new HTTPError('source unavailable', 503), true],
    ['connection error', Object.assign(new Error('source unreachable'), { code: 'ECONNREFUSED' }), true],
  ])('row 26: wraps a custom source %s without sending a request', async (_label, cause, retryable) => {
    const actor = () => { throw cause; };
    const client = new TokenExchangeClient(ISSUER, { actor });

    const failure = client.exchangeToken({ subjectToken: 'subject' });
    await expect(failure).rejects.toBeInstanceOf(WorkloadIdentityRuntimeError);
    await expect(failure).rejects.toMatchObject({ source: 'custom', retryable });
    await expect(failure).rejects.toHaveProperty('cause', cause);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('bounds the token request with a timeout by default', async () => {
    const client = new TokenExchangeClient(ISSUER, { clientId: 'app', clientSecret: 'shh' });
    await client.exchangeToken({ subjectToken: 'subject' });

    const tokenCall = fetchMock.mock.calls.find(([url]) => url === TOKEN_ENDPOINT);
    expect((tokenCall![1] as RequestInit).signal).toBeInstanceOf(AbortSignal);
  });

  it('rejects with a TimeoutError when the token endpoint does not answer within fetchTimeoutMs', async () => {
    fetchMock.mockImplementation(async (input: FetchInput, init?: FetchInit) => {
      const url = typeof input === 'string' ? input : (input as URL | Request).toString();
      if (url.includes('/.well-known/oauth-authorization-server')) {
        return mockMetadataResponse();
      }
      return hangUntilAborted(init);
    });

    const client = new TokenExchangeClient(ISSUER, { clientId: 'app', clientSecret: 'shh', fetchTimeoutMs: 50 });
    const failure = client.exchangeToken({ subjectToken: 'subject' });
    await expect(failure).rejects.toMatchObject({ name: 'TimeoutError' });
    const tokenCall = fetchMock.mock.calls.find(([url]) => url === TOKEN_ENDPOINT);
    await expect(failure).rejects.toBe((tokenCall![1] as RequestInit).signal!.reason);
  });

  it.each(['TimeoutError', 'AbortError'])('preserves the timeout reason when the body rejects with %s', async (errorName) => {
    fetchMock.mockImplementation(async (input: FetchInput, init?: FetchInit) => {
      if (input !== TOKEN_ENDPOINT) return mockMetadataResponse();
      const signal = init!.signal!;
      return new Response(new ReadableStream({
        start(controller) {
          signal.addEventListener('abort', () => {
            const cause = errorName === 'AbortError'
              ? new DOMException('The operation was aborted.', 'AbortError')
              : signal.reason;
            controller.error(cause);
          });
        },
      }));
    });

    const client = new TokenExchangeClient(ISSUER, { fetchTimeoutMs: 50 });
    const failure = client.exchangeToken({ subjectToken: 'subject' });
    await expect(failure).rejects.toBeInstanceOf(DOMException);
    await expect(failure).rejects.toMatchObject({ name: 'TimeoutError' });
    const tokenCall = fetchMock.mock.calls.find(([url]) => url === TOKEN_ENDPOINT);
    await expect(failure).rejects.toBe((tokenCall![1] as RequestInit).signal!.reason);
  });

  it('preserves the HTTP status, code, description and URI of a token endpoint error', async () => {
    const errorUri = 'https://auth.example.com/errors/unauthorized-client';
    const description = 'Client is not permitted to impersonate';
    fetchMock.mockImplementation(async (input: FetchInput) => {
      if (input !== TOKEN_ENDPOINT) return mockMetadataResponse();
      return Response.json({
        error: 'unauthorized_client',
        error_description: description,
        error_uri: errorUri,
      }, { status: 429 });
    });

    const client = new TokenExchangeClient(ISSUER);
    const failure = client.impersonate({ userIdentifier: 'user@example.com', resource: 'https://api.example.com' });
    await expect(failure).rejects.toBeInstanceOf(OAuthError);
    await expect(failure).rejects.toMatchObject({
      status: 429,
      errorCode: 'unauthorized_client',
      message: description,
      errorDescription: description,
      errorUri,
      retryable: true,
    });
  });

  it('preserves the HTTP status when the token endpoint sends no OAuth error body', async () => {
    fetchMock.mockImplementation(async (input: FetchInput) =>
      input === TOKEN_ENDPOINT ? new Response('Service unavailable', { status: 503 }) : mockMetadataResponse(),
    );

    const client = new TokenExchangeClient(ISSUER);
    const failure = client.impersonate({ userIdentifier: 'user@example.com', resource: 'https://api.example.com' });
    await expect(failure).rejects.toBeInstanceOf(OAuthError);
    await expect(failure).rejects.toMatchObject({
      status: 503,
      errorCode: 'invalid_response',
      message: 'Token exchange failed (HTTP 503)',
      retryable: true,
    });
  });

  it('reports a network failure without a response status', async () => {
    const cause = new TypeError('fetch failed');
    fetchMock.mockImplementation(async (input: FetchInput) => {
      if (input === TOKEN_ENDPOINT) throw cause;
      return mockMetadataResponse();
    });

    const client = new TokenExchangeClient(ISSUER);
    const error = await client.impersonate({
      userIdentifier: 'user@example.com',
      resource: 'https://api.example.com',
    }).catch((error: unknown) => error);
    expect(error).toBeInstanceOf(HTTPError);
    expect(error).toMatchObject({ status: undefined, message: 'fetch failed' });
    expect((error as HTTPError).cause).toBe(cause);
  });

  it.each([200, 503])('preserves the cause of a body read failure after HTTP %s', async (status) => {
    const cause = new Error('response stream failed');
    fetchMock.mockImplementation(async (input: FetchInput) => {
      if (input !== TOKEN_ENDPOINT) return mockMetadataResponse();
      return new Response(new ReadableStream({
        start(controller) {
          controller.error(cause);
        },
      }), { status });
    });

    const client = new TokenExchangeClient(ISSUER);
    const error = await client.exchangeToken({ subjectToken: 'subject' }).catch((error: unknown) => error);
    expect(error).toBeInstanceOf(HTTPError);
    expect(error).toMatchObject({ status: undefined, message: 'response stream failed' });
    expect((error as HTTPError).cause).toBe(cause);
  });

  it('throws on missing userIdentifier', async () => {
    const client = new TokenExchangeClient(ISSUER, { clientId: 'app', clientSecret: 'shh' });
    await expect(
      client.impersonate({ userIdentifier: '', resource: 'https://api.example.com' }),
    ).rejects.toThrow(/userIdentifier is required/);
  });
});

describe('deserializeTokenResponse', () => {
  it('defaults token_type to Bearer when the server omits it', async () => {
    const { deserializeTokenResponse } = await import('./tokenExchange.js');
    const response = deserializeTokenResponse({ access_token: 'tok' });
    expect(response.tokenType).toBe('Bearer');
  });

  it('throws OAuthError("invalid_response") when access_token is missing', async () => {
    const { deserializeTokenResponse } = await import('./tokenExchange.js');
    let thrown: unknown;
    try {
      deserializeTokenResponse({ token_type: 'Bearer' });
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(OAuthError);
    expect((thrown as OAuthError).errorCode).toBe('invalid_response');
  });

  it('parses id_token when present', async () => {
    const { deserializeTokenResponse } = await import('./tokenExchange.js');
    const response = deserializeTokenResponse({
      access_token: 'tok',
      token_type: 'Bearer',
      id_token: 'oidc-id-token',
    });
    expect(response.idToken).toBe('oidc-id-token');
  });

  it('omits idToken when the server does not return one', async () => {
    const { deserializeTokenResponse } = await import('./tokenExchange.js');
    const response = deserializeTokenResponse({ access_token: 'tok', token_type: 'Bearer' });
    expect(response.idToken).toBeUndefined();
  });
});
