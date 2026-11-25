import { jest } from '@jest/globals';
import { fetchAuthorizationServerMetadata } from './discovery.js';
import { HTTPError, OAuthError } from './errors.js';

const ISSUER = 'https://auth.example.com';

type FetchInput = Parameters<typeof fetch>[0];

describe('fetchAuthorizationServerMetadata', () => {
  let originalFetch: typeof fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  function mockFetch(body: Record<string, unknown>, status = 200): void {
    globalThis.fetch = jest.fn(async (_input: FetchInput) =>
      new Response(JSON.stringify(body), {
        status,
        headers: { 'content-type': 'application/json' },
      }),
    ) as unknown as typeof fetch;
  }

  it('types grant_types_supported and response_types_supported', async () => {
    mockFetch({
      issuer: ISSUER,
      token_endpoint: `${ISSUER}/token`,
      grant_types_supported: ['authorization_code', 'client_credentials'],
      response_types_supported: ['code'],
    });

    const metadata = await fetchAuthorizationServerMetadata(ISSUER);

    expect(metadata.grant_types_supported).toEqual([
      'authorization_code',
      'client_credentials',
    ]);
    expect(metadata.response_types_supported).toEqual(['code']);
  });

  it('leaves the supported-arrays undefined when absent', async () => {
    mockFetch({ issuer: ISSUER });

    const metadata = await fetchAuthorizationServerMetadata(ISSUER);

    expect(metadata.grant_types_supported).toBeUndefined();
    expect(metadata.response_types_supported).toBeUndefined();
  });

  it.each([
    {
      name: 'present',
      body: { issuer: ISSUER, device_authorization_endpoint: `${ISSUER}/device` },
      expected: `${ISSUER}/device`,
    },
    { name: 'absent', body: { issuer: ISSUER }, expected: undefined },
  ])('types device_authorization_endpoint when $name', async ({ body, expected }) => {
    mockFetch(body);

    const metadata = await fetchAuthorizationServerMetadata(ISSUER);
    const endpoint: string | undefined = metadata.device_authorization_endpoint;

    expect(endpoint).toBe(expected);
  });

  it('rejects a device_authorization_endpoint that is not a string', async () => {
    mockFetch({ issuer: ISSUER, device_authorization_endpoint: 42 });

    await expect(fetchAuthorizationServerMetadata(ISSUER)).rejects.toMatchObject({
      errorCode: 'invalid_response',
    });
  });

  it('authorization server discovery row 12: types both revocation fields', async () => {
    const endpoint = `${ISSUER}/revoke`;
    const methods = ['client_secret_basic', 'client_secret_post', 'private_key_jwt', 'none'];
    mockFetch({
      issuer: ISSUER,
      revocation_endpoint: endpoint,
      revocation_endpoint_auth_methods_supported: methods,
    });

    const metadata = await fetchAuthorizationServerMetadata(ISSUER);
    const typedEndpoint: string | undefined = metadata.revocation_endpoint;
    const typedMethods: string[] | undefined = metadata.revocation_endpoint_auth_methods_supported;
    expect(typedEndpoint).toBe(endpoint);
    expect(typedMethods).toEqual(methods);
  });

  it('authorization server discovery row 13: leaves both revocation fields undefined when absent', async () => {
    mockFetch({ issuer: ISSUER });

    const metadata = await fetchAuthorizationServerMetadata(ISSUER);
    expect(metadata.revocation_endpoint).toBeUndefined();
    expect(metadata.revocation_endpoint_auth_methods_supported).toBeUndefined();
  });

  it.each([
    ['revocation_endpoint', 42],
    ['revocation_endpoint_auth_methods_supported', 'none'],
    ['revocation_endpoint_auth_methods_supported', [false]],
  ])('rejects an incorrectly typed %s value %p', async (field, value) => {
    mockFetch({ issuer: ISSUER, [field]: value });

    await expect(fetchAuthorizationServerMetadata(ISSUER)).rejects.toMatchObject({
      errorCode: 'invalid_response',
    });
  });

  it('throws HTTPError on a non-2xx response', async () => {
    mockFetch({}, 503);

    await expect(fetchAuthorizationServerMetadata(ISSUER)).rejects.toBeInstanceOf(
      HTTPError,
    );
  });

  it('throws OAuthError("issuer_mismatch") when the issuer does not match', async () => {
    mockFetch({ issuer: 'https://evil.example.com' });

    await expect(fetchAuthorizationServerMetadata(ISSUER)).rejects.toMatchObject({
      errorCode: 'issuer_mismatch',
    });
  });

  it('accepts an issuer that differs only by a trailing slash', async () => {
    mockFetch({ issuer: `${ISSUER}/` });

    const metadata = await fetchAuthorizationServerMetadata(ISSUER);

    expect(metadata.issuer).toBe(`${ISSUER}/`);
  });

  it('throws OAuthError("invalid_response") when the issuer field is missing', async () => {
    mockFetch({ token_endpoint: `${ISSUER}/token` });

    const error = await fetchAuthorizationServerMetadata(ISSUER).catch((e) => e);
    expect(error).toBeInstanceOf(OAuthError);
    expect((error as OAuthError).errorCode).toBe('invalid_response');
  });
});
