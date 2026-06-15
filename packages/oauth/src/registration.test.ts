import { jest } from '@jest/globals';
import { registerClient } from './registration.js';
import { OAuthError } from './errors.js';

const ISSUER = 'https://auth.example.com';
const REGISTRATION_ENDPOINT = 'https://auth.example.com/register';

type FetchInput = Parameters<typeof fetch>[0];
type FetchInit = Parameters<typeof fetch>[1];

function metadataResponse(extra: Record<string, unknown> = {}): Response {
  return new Response(
    JSON.stringify({ issuer: ISSUER, registration_endpoint: REGISTRATION_ENDPOINT, ...extra }),
    { status: 200, headers: { 'content-type': 'application/json' } },
  );
}

function metadataResponseWithoutRegistration(): Response {
  return new Response(
    JSON.stringify({ issuer: ISSUER, token_endpoint: 'https://auth.example.com/token' }),
    { status: 200, headers: { 'content-type': 'application/json' } },
  );
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

describe('registerClient', () => {
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

  it('posts the registration body and returns the parsed response', async () => {
    fetchMock.mockImplementationOnce(async () => metadataResponse());
    fetchMock.mockImplementationOnce(async () =>
      jsonResponse(201, {
        client_id: 'svc-abc',
        client_secret: 'sec',
        client_id_issued_at: 1700000000,
        client_name: 'My Service',
        redirect_uris: ['https://app.example.com/callback'],
        grant_types: ['client_credentials'],
        scope: 'read write',
      }),
    );

    const response = await registerClient(ISSUER, {
      clientName: 'My Service',
      redirectUris: ['https://app.example.com/callback'],
      grantTypes: ['client_credentials'],
      scope: 'read write',
    });

    expect(response.clientId).toBe('svc-abc');
    expect(response.clientSecret).toBe('sec');
    expect(response.clientIdIssuedAt).toBe(1700000000);
    expect(response.clientName).toBe('My Service');
    expect(response.redirectUris).toEqual(['https://app.example.com/callback']);
    expect(response.grantTypes).toEqual(['client_credentials']);
    expect(response.scope).toEqual(['read', 'write']);
    expect(response.raw).toMatchObject({ client_id: 'svc-abc', client_secret: 'sec' });
  });

  it('throws when the AS does not advertise registration_endpoint', async () => {
    fetchMock.mockImplementationOnce(async () => metadataResponseWithoutRegistration());

    await expect(registerClient(ISSUER, { clientName: 'svc' })).rejects.toThrow(
      /does not advertise a registration_endpoint/,
    );
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('throws OAuthError when the AS returns an RFC 6749 error response', async () => {
    fetchMock.mockImplementationOnce(async () => metadataResponse());
    fetchMock.mockImplementationOnce(async () =>
      jsonResponse(400, {
        error: 'invalid_client_metadata',
        error_description: 'redirect_uris is required',
        error_uri: 'https://docs.example.com/errors',
      }),
    );

    let thrown: unknown;
    try {
      await registerClient(ISSUER, { clientName: 'svc' });
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(OAuthError);
    const err = thrown as OAuthError;
    expect(err.errorCode).toBe('invalid_client_metadata');
    expect(err.message).toBe('redirect_uris is required');
    expect(err.errorUri).toBe('https://docs.example.com/errors');
  });

  it('throws OAuthError("invalid_response") on non-OAuth HTTP failures', async () => {
    fetchMock.mockImplementationOnce(async () => metadataResponse());
    fetchMock.mockImplementationOnce(async () => new Response('upstream blew up', { status: 502 }));

    let thrown: unknown;
    try {
      await registerClient(ISSUER, { clientName: 'svc' });
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(OAuthError);
    expect((thrown as OAuthError).errorCode).toBe('invalid_response');
    expect((thrown as OAuthError).message).toContain('HTTP 502');
  });

  it('throws OAuthError("invalid_response") when the response is missing client_id', async () => {
    fetchMock.mockImplementationOnce(async () => metadataResponse());
    fetchMock.mockImplementationOnce(async () => jsonResponse(200, { client_secret: 'orphan' }));

    let thrown: unknown;
    try {
      await registerClient(ISSUER, { clientName: 'svc' });
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(OAuthError);
    expect((thrown as OAuthError).errorCode).toBe('invalid_response');
    expect((thrown as OAuthError).message).toContain('missing client_id');
  });

  it('passes additionalMetadata fields through and surfaces them in raw', async () => {
    fetchMock.mockImplementationOnce(async () => metadataResponse());
    fetchMock.mockImplementationOnce(async () =>
      jsonResponse(201, {
        client_id: 'svc-abc',
        'kc:zone_id': 'zone-a',
        custom_extension: 'vendor-value',
      }),
    );

    const response = await registerClient(ISSUER, {
      clientName: 'svc',
      additionalMetadata: { 'kc:zone_id': 'zone-a' },
    });

    expect(response.clientId).toBe('svc-abc');
    expect(response.raw['kc:zone_id']).toBe('zone-a');
    expect(response.raw['custom_extension']).toBe('vendor-value');
  });

  it('named fields take precedence over additionalMetadata with the same key', async () => {
    fetchMock.mockImplementationOnce(async () => metadataResponse());
    fetchMock.mockImplementationOnce(async () => jsonResponse(201, { client_id: 'svc-abc' }));

    await registerClient(ISSUER, {
      clientName: 'Real Name',
      additionalMetadata: { client_name: 'Overridden Name' },
    });

    const [, registrationCall] = fetchMock.mock.calls;
    const body = JSON.parse((registrationCall![1] as RequestInit).body as string);
    expect(body.client_name).toBe('Real Name');
  });

  it('sends the initial access token as a Bearer credential on the registration request', async () => {
    fetchMock.mockImplementationOnce(async () => metadataResponse());
    fetchMock.mockImplementationOnce(async () => jsonResponse(201, { client_id: 'svc-abc' }));

    await registerClient(
      ISSUER,
      { clientName: 'svc' },
      { initialAccessToken: 'iat-secret-123' },
    );

    const [, registrationCall] = fetchMock.mock.calls;
    const headers = (registrationCall![1] as RequestInit).headers as Record<string, string>;
    expect(headers.Authorization).toBe('Bearer iat-secret-123');
  });

  it('sends no Authorization header when no initial access token is given', async () => {
    fetchMock.mockImplementationOnce(async () => metadataResponse());
    fetchMock.mockImplementationOnce(async () => jsonResponse(201, { client_id: 'svc-abc' }));

    await registerClient(ISSUER, { clientName: 'svc' });

    const [, registrationCall] = fetchMock.mock.calls;
    const headers = (registrationCall![1] as RequestInit).headers as Record<string, string>;
    expect(headers.Authorization).toBeUndefined();
  });

  it('propagates AbortSignal timeout to the fetch call', async () => {
    fetchMock.mockImplementationOnce(async () => metadataResponse());
    fetchMock.mockImplementationOnce(async (_url: unknown, init?: RequestInit) => {
      if (init?.signal?.aborted) throw new DOMException('Aborted', 'AbortError');
      return jsonResponse(201, { client_id: 'svc-abc' });
    });

    const controller = new AbortController();
    controller.abort();

    await expect(
      registerClient(ISSUER, { clientName: 'svc' }, { signal: controller.signal }),
    ).rejects.toThrow();
  });
});
