import { jest } from '@jest/globals';
import { resolveIssuerFromChallenge, authenticateFromChallenge } from './challenge.js';

const METADATA_URL = 'https://api.example.com/.well-known/oauth-protected-resource';
const ISSUER = 'https://auth.example.com';
const RESOURCE = 'https://api.example.com';

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

describe('resolveIssuerFromChallenge', () => {
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

  it('parses a typical Bearer challenge with multiple parameters and resolves the issuer', async () => {
    fetchMock.mockImplementationOnce(async () =>
      jsonResponse(200, {
        resource: RESOURCE,
        authorization_servers: [ISSUER, 'https://auth2.example.com'],
      }),
    );

    const result = await resolveIssuerFromChallenge(
      `Bearer realm="api", error="invalid_token", resource_metadata="${METADATA_URL}", scope="read"`,
    );

    expect(result).toEqual({ issuer: ISSUER, resource: RESOURCE });
    expect(fetchMock).toHaveBeenCalledWith(METADATA_URL, { signal: undefined });
  });

  it('omits resource when the metadata document has none', async () => {
    fetchMock.mockImplementationOnce(async () =>
      jsonResponse(200, { authorization_servers: [ISSUER] }),
    );

    const result = await resolveIssuerFromChallenge(
      `Bearer resource_metadata="${METADATA_URL}"`,
    );

    expect(result.issuer).toBe(ISSUER);
    expect(result.resource).toBeUndefined();
  });

  it('accepts an unquoted resource_metadata value', async () => {
    fetchMock.mockImplementationOnce(async () =>
      jsonResponse(200, { authorization_servers: [ISSUER] }),
    );

    const result = await resolveIssuerFromChallenge(
      `Bearer resource_metadata=${METADATA_URL}, realm="api"`,
    );

    expect(result.issuer).toBe(ISSUER);
    expect(fetchMock).toHaveBeenCalledWith(METADATA_URL, { signal: undefined });
  });

  it('throws when the header has no resource_metadata parameter', async () => {
    await expect(
      resolveIssuerFromChallenge('Bearer realm="api", error="invalid_token"'),
    ).rejects.toThrow(/resource_metadata/);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('throws on a non-OK metadata fetch', async () => {
    fetchMock.mockImplementationOnce(async () => jsonResponse(404, { error: 'not found' }));

    await expect(
      resolveIssuerFromChallenge(`Bearer resource_metadata="${METADATA_URL}"`),
    ).rejects.toThrow(/HTTP 404/);
  });

  it('throws when the document is not a JSON object', async () => {
    fetchMock.mockImplementationOnce(async () =>
      new Response('not json', { status: 200, headers: { 'content-type': 'text/plain' } }),
    );

    await expect(
      resolveIssuerFromChallenge(`Bearer resource_metadata="${METADATA_URL}"`),
    ).rejects.toThrow(/not valid JSON/);
  });

  it('throws when authorization_servers is missing, empty, or not all strings', async () => {
    for (const body of [
      { resource: RESOURCE },
      { authorization_servers: [] },
      { authorization_servers: [42] },
      { authorization_servers: 'not-an-array' },
    ]) {
      fetchMock.mockImplementationOnce(async () => jsonResponse(200, body));
      await expect(
        resolveIssuerFromChallenge(`Bearer resource_metadata="${METADATA_URL}"`),
      ).rejects.toThrow(/authorization_servers/);
    }
  });
});

describe('authenticateFromChallenge', () => {
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

  function mockFetchRouting(): void {
    fetchMock.mockImplementation(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url === METADATA_URL) {
        return jsonResponse(200, {
          resource: RESOURCE,
          authorization_servers: [ISSUER],
        });
      }
      if (url.includes('/.well-known/')) {
        return jsonResponse(200, {
          issuer: ISSUER,
          token_endpoint: `${ISSUER}/token`,
          authorization_endpoint: `${ISSUER}/authorize`,
        });
      }
      return jsonResponse(200, { access_token: 'challenge-tok', token_type: 'bearer' });
    });
  }

  it('resolves the issuer from the challenge and defaults resource from the metadata document', async () => {
    mockFetchRouting();
    const testPort = 19880;

    let authorizeUrl: string | undefined;
    const authPromise = authenticateFromChallenge(
      `Bearer resource_metadata="${METADATA_URL}"`,
      {
        clientId: 'my-client',
        port: testPort,
        timeoutMs: 5000,
        openBrowser: (url) => {
          authorizeUrl = url;
        },
      },
    );

    // Give the loopback server time to start (see pkce.test.ts).
    await new Promise((r) => setTimeout(r, 250));

    expect(authorizeUrl).toBeDefined();
    const parsed = new URL(authorizeUrl!);
    // Resolved issuer's authorization endpoint is used.
    expect(parsed.origin + parsed.pathname).toBe(`${ISSUER}/authorize`);
    // Resource defaults to the metadata document's resource identifier.
    expect(parsed.searchParams.get('resource')).toBe(RESOURCE);
    const state = parsed.searchParams.get('state');
    expect(state).toBeTruthy();

    await originalFetch(
      `http://localhost:${testPort}/callback?code=auth-code-xyz&state=${encodeURIComponent(state!)}`,
    );

    const result = await authPromise;
    expect(result.accessToken).toBe('challenge-tok');
  }, 8000);

  it('keeps a caller-supplied resource over the metadata document resource', async () => {
    mockFetchRouting();
    const testPort = 19881;
    const callerResource = 'https://other.example.com';

    let authorizeUrl: string | undefined;
    const authPromise = authenticateFromChallenge(
      `Bearer resource_metadata="${METADATA_URL}"`,
      {
        clientId: 'my-client',
        port: testPort,
        timeoutMs: 5000,
        resource: callerResource,
        openBrowser: (url) => {
          authorizeUrl = url;
        },
      },
    );

    await new Promise((r) => setTimeout(r, 250));

    expect(authorizeUrl).toBeDefined();
    const parsed = new URL(authorizeUrl!);
    expect(parsed.searchParams.get('resource')).toBe(callerResource);
    const state = parsed.searchParams.get('state');

    await originalFetch(
      `http://localhost:${testPort}/callback?code=auth-code-xyz&state=${encodeURIComponent(state!)}`,
    );

    await authPromise;
  }, 8000);

  it('rejects without starting the flow when the challenge has no resource_metadata', async () => {
    await expect(
      authenticateFromChallenge('Bearer realm="api"', { clientId: 'my-client' }),
    ).rejects.toThrow(/resource_metadata/);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
