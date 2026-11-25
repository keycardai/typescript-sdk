import { jest } from '@jest/globals';
import { TokenExchangeClient } from './tokenExchange.js';
import { ClientCredentialsClient } from './clientCredentials.js';
import { TokenEndpointResolver, DEFAULT_DISCOVERY_TTL_MS, DEFAULT_NEGATIVE_TTL_MS } from './tokenEndpoint.js';
import { TokenEndpointDiscoveryError } from './errors.js';
import { fetchAuthorizationServerMetadata } from './discovery.js';

const ISSUER = 'https://auth.example.com';
const TOKEN_ENDPOINT = 'https://auth.example.com/token';
const METADATA_PATH = '/.well-known/oauth-authorization-server';

type FetchInput = Parameters<typeof fetch>[0];
type FetchInit = Parameters<typeof fetch>[1];

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function metadataResponse(overrides: Record<string, unknown> = {}): Response {
  return jsonResponse({ issuer: ISSUER, token_endpoint: TOKEN_ENDPOINT, ...overrides });
}

function tokenResponse(): Response {
  return jsonResponse({ access_token: 'issued-token', token_type: 'Bearer', expires_in: 3600 });
}

/**
 * A fetch mock that serves the token endpoint normally and delegates metadata
 * requests to a per-test queue: each entry is consumed once, the last entry
 * repeats for any further request.
 */
function installFetch(metadataOutcomes: Array<() => Response | Promise<Response>>) {
  const outcomes = [...metadataOutcomes];
  let metadataCalls = 0;
  const fetchMock = jest.fn(async (input: FetchInput, _init?: FetchInit) => {
    const url = typeof input === 'string' ? input : (input as URL | Request).toString();
    if (url.includes(METADATA_PATH)) {
      metadataCalls += 1;
      const next = outcomes.length > 1 ? outcomes.shift()! : outcomes[0]!;
      return next();
    }
    if (url === TOKEN_ENDPOINT) {
      return tokenResponse();
    }
    throw new Error(`unexpected fetch: ${url}`);
  });
  globalThis.fetch = fetchMock as unknown as typeof fetch;
  return { fetchMock, metadataCalls: () => metadataCalls };
}

const networkError = () => Promise.reject(new TypeError('fetch failed'));
const ok = () => metadataResponse();
const status = (code: number) => () => jsonResponse({ error: 'nope' }, code);

interface Path {
  name: string;
  row: number;
  make(options?: { discoveryTtlMs?: number; negativeTtlMs?: number }): { call(): Promise<unknown> };
}

const paths: Path[] = [
  {
    name: 'TokenExchangeClient.exchangeToken',
    row: 8,
    make(options) {
      const client = new TokenExchangeClient(ISSUER, { clientId: 'app', clientSecret: 'shh', ...options });
      return { call: () => client.exchangeToken({ subjectToken: 'subject', resource: 'https://api.example.com' }) };
    },
  },
  {
    name: 'ClientCredentialsClient.requestToken',
    row: 7,
    make(options) {
      const client = new ClientCredentialsClient(ISSUER, { clientId: 'app', clientSecret: 'shh', ...options });
      return { call: () => client.requestToken({ resource: 'https://api.example.com' }) };
    },
  },
];

async function rejection(promise: Promise<unknown>): Promise<TokenEndpointDiscoveryError> {
  try {
    await promise;
  } catch (e) {
    expect(e).toBeInstanceOf(TokenEndpointDiscoveryError);
    return e as TokenEndpointDiscoveryError;
  }
  throw new Error('expected the call to reject');
}

describe.each(paths)('token endpoint discovery via $name', ({ make, row }) => {
  let originalFetch: typeof fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
    jest.useFakeTimers();
    jest.setSystemTime(new Date('2026-01-01T00:00:00Z'));
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    jest.useRealTimers();
  });

  it(`row ${row}: a network error paces the next discovery request`, async () => {
    const fetch = installFetch([networkError, ok]);
    const { call } = make();

    const error = await rejection(call());
    expect(error.retryable).toBe(true);
    expect(error.cause).toBeInstanceOf(TypeError);

    expect(await rejection(call())).toBe(error);
    expect(fetch.metadataCalls()).toBe(1);
    jest.advanceTimersByTime(1200);
    await expect(call()).resolves.toBeDefined();
    expect(fetch.metadataCalls()).toBe(2);
  });

  it.each([500, 503, 429])('base row 3: HTTP %i is transient; headerless 429 is not paced', async (code) => {
    const fetch = installFetch([status(code), ok]);
    const { call } = make();

    const error = await rejection(call());
    expect(error.retryable).toBe(true);
    if (code !== 429) {
      expect(await rejection(call())).toBe(error);
      expect(fetch.metadataCalls()).toBe(1);
      jest.advanceTimersByTime(1200);
    }

    await expect(call()).resolves.toBeDefined();
    expect(fetch.metadataCalls()).toBe(2);
  });

  it('a 404 is remembered for negativeTtl, then discovery runs again', async () => {
    const fetch = installFetch([status(404), ok]);
    const { call } = make();

    const first = await rejection(call());
    expect(first.retryable).toBe(false);

    const second = await rejection(call());
    expect(second).toBe(first);
    expect(fetch.metadataCalls()).toBe(1);

    jest.advanceTimersByTime(DEFAULT_NEGATIVE_TTL_MS);
    await expect(call()).resolves.toBeDefined();
    expect(fetch.metadataCalls()).toBe(2);
  });

  it('an issuer mismatch is deterministic and remembered', async () => {
    const fetch = installFetch([() => metadataResponse({ issuer: 'https://other.example.com' }), ok]);
    const { call } = make();

    const error = await rejection(call());
    expect(error.retryable).toBe(false);
    await rejection(call());
    expect(fetch.metadataCalls()).toBe(1);
  });

  it('base row 5: metadata without token_endpoint is deterministic and expires by negativeTtl', async () => {
    const fetch = installFetch([() => metadataResponse({ token_endpoint: undefined }), ok]);
    const { call } = make();

    const error = await rejection(call());
    expect(error.message).toMatch(/does not advertise a token_endpoint/);
    expect(error.retryable).toBe(false);

    await rejection(call());
    expect(fetch.metadataCalls()).toBe(1);

    jest.advanceTimersByTime(DEFAULT_NEGATIVE_TTL_MS);
    await expect(call()).resolves.toBeDefined();
    expect(fetch.metadataCalls()).toBe(2);
  });

  it('negativeTtlMs 0 disables negative caching', async () => {
    const fetch = installFetch([status(404), status(404), ok]);
    const { call } = make({ negativeTtlMs: 0 });

    await rejection(call());
    await rejection(call());
    expect(fetch.metadataCalls()).toBe(2);

    await expect(call()).resolves.toBeDefined();
    expect(fetch.metadataCalls()).toBe(3);
  });

  it('negativeTtl never exceeds discoveryTtl', async () => {
    const fetch = installFetch([status(404), ok]);
    const { call } = make({ discoveryTtlMs: 10_000 });

    await rejection(call());
    jest.advanceTimersByTime(10_000);
    await expect(call()).resolves.toBeDefined();
    expect(fetch.metadataCalls()).toBe(2);
  });

  it('concurrent cold-cache calls share one discovery request', async () => {
    const fetch = installFetch([ok]);
    const { call } = make();

    await Promise.all([call(), call(), call()]);
    expect(fetch.metadataCalls()).toBe(1);
  });

  it('concurrent cold-cache calls see the shared failure and later calls can fetch after pacing', async () => {
    const fetch = installFetch([networkError, ok]);
    const { call } = make();

    const results = await Promise.allSettled([call(), call()]);
    expect(results.map((r) => r.status)).toEqual(['rejected', 'rejected']);
    expect(fetch.metadataCalls()).toBe(1);

    jest.advanceTimersByTime(1200);
    await expect(call()).resolves.toBeDefined();
    expect(fetch.metadataCalls()).toBe(2);
  });

  it('caches the endpoint for discoveryTtl and discovers again after it elapses', async () => {
    const fetch = installFetch([ok]);
    const { call } = make();

    await call();
    jest.advanceTimersByTime(DEFAULT_DISCOVERY_TTL_MS - 1);
    await call();
    expect(fetch.metadataCalls()).toBe(1);

    jest.advanceTimersByTime(1);
    await call();
    expect(fetch.metadataCalls()).toBe(2);
  });

  it('honors a custom discoveryTtlMs', async () => {
    const fetch = installFetch([ok]);
    const { call } = make({ discoveryTtlMs: 5_000 });

    await call();
    jest.advanceTimersByTime(5_000);
    await call();
    expect(fetch.metadataCalls()).toBe(2);
  });

  it.each([429, 503])('base row 2: honors and caps Retry-After on HTTP %i', async (code) => {
    for (const seconds of [5, 120]) {
      for (const format of ['seconds', 'imf', 'rfc850', 'asctime', 'asctimeZeroPadded'] as const) {
        const date = new Date(Date.now() + seconds * 1000);
        const imf = date.toUTCString();
        const [weekday, day, month, year, time] = imf.replace(',', '').split(' ');
        const header = {
          seconds: String(seconds),
          imf,
          rfc850: `${date.toLocaleDateString('en-US', { weekday: 'long', timeZone: 'UTC' })}, ${day}-${month}-${year.slice(2)} ${time} GMT`,
          asctime: `${weekday} ${month} ${day.trimStart().replace(/^0/, ' ')} ${time} ${year}`,
          asctimeZeroPadded: `${weekday} ${month} ${day} ${time} ${year}`,
        }[format];
        const fetch = installFetch([() => new Response('', { status: code, headers: { 'Retry-After': header } }), ok]);
        const { call } = make();
        const error = await rejection(call());
        jest.advanceTimersByTime(Math.min(60, seconds) * 1000 - 1);
        expect(await rejection(call())).toBe(error);
        expect(fetch.metadataCalls()).toBe(1);
        jest.advanceTimersByTime(1);
        await expect(call()).resolves.toBeDefined();
      }
    }
  });

  it('base rows 3 and 4: caps exponential delays and resets on success', async () => {
    const fetch = installFetch([...Array<() => Promise<Response>>(7).fill(networkError), ok, networkError, ok]);
    const { call } = make({ discoveryTtlMs: 5000 });
    for (const [index, nominal] of [1000, 2000, 4000, 8000, 16000, 32000, 64000].entries()) {
      const error = await rejection(call());
      const lower = Math.min(30000, nominal * 0.8) - 1;
      jest.advanceTimersByTime(lower);
      expect(await rejection(call())).toBe(error);
      expect(fetch.metadataCalls()).toBe(index + 1);
      jest.advanceTimersByTime(Math.min(30000, nominal * 1.2) - lower);
    }
    await expect(call()).resolves.toBeDefined();
    jest.advanceTimersByTime(5000);
    await rejection(call());
    jest.advanceTimersByTime(1200);
    await expect(call()).resolves.toBeDefined();
  });

  it('authorization server discovery row 11: standalone discovery does not reuse cached failures', async () => {
    const fetch = installFetch([() => new Response('', { status: 503, headers: { 'Retry-After': '5' } }), ok]);
    const { call } = make();
    const error = await rejection(call());
    jest.advanceTimersByTime(4999);
    expect(await rejection(call())).toBe(error);
    expect(fetch.metadataCalls()).toBe(1);
    await expect(fetchAuthorizationServerMetadata(ISSUER)).resolves.toBeDefined();
    expect(fetch.metadataCalls()).toBe(2);
    jest.advanceTimersByTime(1);
    await expect(call()).resolves.toBeDefined();
    expect(fetch.metadataCalls()).toBe(3);
  });
});

describe('TokenEndpointResolver internal fetch bound', () => {
  let originalFetch: typeof fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('a hung discovery is aborted by the internal timeout and paces the next fetch', async () => {
    let calls = 0;
    globalThis.fetch = jest.fn(async (_input: FetchInput, init?: FetchInit) => {
      calls += 1;
      if (calls === 1) {
        return new Promise<Response>((_, reject) => {
          init?.signal?.addEventListener('abort', () => reject(init.signal!.reason));
        });
      }
      return metadataResponse();
    }) as unknown as typeof fetch;

    const resolver = new TokenEndpointResolver(ISSUER, { fetchTimeoutMs: 20 });

    const error = await rejection(resolver.resolve());
    expect(error.retryable).toBe(true);

    expect(await rejection(resolver.resolve())).toBe(error);
    const clock = jest.spyOn(performance, 'now').mockReturnValue(performance.now() + 1200);
    try {
      await expect(resolver.resolve()).resolves.toBe(TOKEN_ENDPOINT);
    } finally {
      clock.mockRestore();
    }
    expect(calls).toBe(2);
  });
});
