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
    expect(response.redirectUris).toEqual(['https://app.example.com/callback']);
    expect(response.grantTypes).toEqual(['client_credentials']);
    expect(response.scope).toEqual(['read', 'write']);

    const [, registrationCall] = fetchMock.mock.calls;
    expect(registrationCall[0]).toBe(REGISTRATION_ENDPOINT);
    const init = registrationCall[1] as FetchInit;
    expect((init as RequestInit).method).toBe('POST');
    const headers = (init as RequestInit).headers as Record<string, string>;
    expect(headers['Content-Type']).toBe('application/json');
    expect(headers['Accept']).toBe('application/json');
    const body = JSON.parse((init as RequestInit).body as string);
    expect(body).toEqual({
      client_name: 'My Service',
      redirect_uris: ['https://app.example.com/callback'],
      grant_types: ['client_credentials'],
      scope: 'read write',
    });
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

  it('throws a generic Error on non-OAuth HTTP failures', async () => {
    fetchMock.mockImplementationOnce(async () => metadataResponse());
    fetchMock.mockImplementationOnce(async () => new Response('upstream blew up', { status: 502 }));

    await expect(registerClient(ISSUER, { clientName: 'svc' })).rejects.toThrow(
      /Client registration failed \(HTTP 502\)/,
    );
  });

  it('throws when the response is missing client_id', async () => {
    fetchMock.mockImplementationOnce(async () => metadataResponse());
    fetchMock.mockImplementationOnce(async () => jsonResponse(200, { client_secret: 'orphan' }));

    await expect(registerClient(ISSUER, { clientName: 'svc' })).rejects.toThrow(
      /missing client_id/,
    );
  });

  it('passes additionalMetadata fields through verbatim', async () => {
    fetchMock.mockImplementationOnce(async () => metadataResponse());
    fetchMock.mockImplementationOnce(async () => jsonResponse(201, { client_id: 'svc-abc' }));

    await registerClient(ISSUER, {
      clientName: 'svc',
      additionalMetadata: { 'kc:zone_id': 'zone-a', software_statement: 'opaque' },
    });

    const [, registrationCall] = fetchMock.mock.calls;
    const body = JSON.parse((registrationCall[1] as RequestInit).body as string);
    expect(body['kc:zone_id']).toBe('zone-a');
    expect(body.software_statement).toBe('opaque');
  });
});
