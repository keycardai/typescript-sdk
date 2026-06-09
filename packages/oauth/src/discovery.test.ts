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
