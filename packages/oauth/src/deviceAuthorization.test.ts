import { jest } from '@jest/globals';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  pollDeviceToken,
  requestDeviceAuthorization,
  systemClock,
  waitForDeviceToken,
  type Clock,
  type DeviceAuthorization,
} from './deviceAuthorization.js';
import type { ApplicationCredential, ClientAuthentication } from './credentials.js';
import { ConfigurationError, DeviceGrantError, DevicePollError, HTTPError, OAuthError, PERMANENT_ERROR_CODES } from './errors.js';
import { WebIdentity } from './server/webIdentity.js';

const ISSUER = 'https://zone.example.com';
const DEVICE_ENDPOINT = `${ISSUER}/oauth/2/device_authorization`;
const TOKEN_ENDPOINT = `${ISSUER}/oauth/2/token`;
const DISCOVERY_URL = `${ISSUER}/.well-known/oauth-authorization-server`;
const RESOURCE_A = 'https://api-a.example.com';
const RESOURCE_B = 'https://api-b.example.com';
const DEVICE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code';
const JWT_BEARER = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
const T0 = Date.UTC(2026, 0, 1);

const METADATA = {
  issuer: ISSUER,
  device_authorization_endpoint: DEVICE_ENDPOINT,
  token_endpoint: TOKEN_ENDPOINT,
};

const DEVICE_RESPONSE = {
  device_code: 'device-code-1',
  user_code: 'WDJB-MJHT',
  verification_uri: `${ISSUER}/device`,
  verification_uri_complete: `${ISSUER}/device?user_code=WDJB-MJHT`,
  expires_in: 600,
  interval: 5,
};

const TOKEN_BODY = {
  access_token: 'access-1',
  token_type: 'Bearer',
  expires_in: 3600,
  scope: 'openid profile',
  refresh_token: 'refresh-1',
  id_token: 'id-token-1',
};

const EXPECTED_TOKEN = {
  accessToken: 'access-1',
  tokenType: 'Bearer',
  expiresIn: 3600,
  scope: ['openid', 'profile'],
  refreshToken: 'refresh-1',
  idToken: 'id-token-1',
};

function authorization(overrides: Partial<DeviceAuthorization> = {}): DeviceAuthorization {
  return {
    deviceCode: 'device-code-1',
    userCode: 'WDJB-MJHT',
    verificationUri: `${ISSUER}/device`,
    expiresIn: 600,
    interval: 5,
    expiresAt: T0 + 600_000,
    ...overrides,
  };
}

/** A clock that records each wait and advances its time by it, without real delay. */
class FakeClock implements Clock {
  time = T0;
  waits: number[] = [];
  onSleep?: (waitNumber: number) => void;

  now(): number {
    return this.time;
  }

  async sleep(ms: number, signal?: AbortSignal): Promise<void> {
    this.waits.push(ms);
    this.time += ms;
    this.onSleep?.(this.waits.length);
    signal?.throwIfAborted();
  }
}

type FetchCall = { url: string; init: RequestInit; body: URLSearchParams; headers: Record<string, string> };
type Responder = (call: FetchCall) => Response | Promise<Response>;

/** Routes discovery to `discovery`, the device endpoint to `device`, and each token endpoint call to the next entry of `polls`. */
function mockFetch(routes: { discovery?: Responder; device?: Responder; polls?: Responder[] }): FetchCall[] {
  const calls: FetchCall[] = [];
  let poll = 0;
  globalThis.fetch = jest.fn(async (input: unknown, init?: unknown) => {
    const requestInit = init as RequestInit;
    const call: FetchCall = {
      url: String(input),
      init: requestInit,
      body: new URLSearchParams(String(requestInit.body)),
      headers: requestInit.headers as Record<string, string>,
    };
    calls.push(call);
    if (call.url === DISCOVERY_URL && routes.discovery) return routes.discovery(call);
    if (call.url === DEVICE_ENDPOINT && routes.device) return routes.device(call);
    if (call.url === TOKEN_ENDPOINT && routes.polls && poll < routes.polls.length) return routes.polls[poll++](call);
    throw new Error(`unexpected request to ${call.url}`);
  }) as unknown as typeof fetch;
  return calls;
}

function json(status: number, body: unknown): Responder {
  return () =>
    new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

/** Never responds. Rejects with the request signal's reason when it aborts. */
const hang: Responder = (call) =>
  new Promise((_resolve, reject) => {
    call.init.signal!.addEventListener('abort', () => reject(call.init.signal!.reason));
  });

/** Sends the status line and headers, then stalls the body until the request signal aborts. */
function stalledBody(status: number): Responder {
  return (call) =>
    new Response(
      new ReadableStream({
        start(controller) {
          call.init.signal!.addEventListener('abort', () => controller.error(call.init.signal!.reason));
        },
      }),
      { status, headers: { 'content-type': 'application/json' } },
    );
}

const pending = json(400, { error: 'authorization_pending' });
const slowDown = json(400, { error: 'slow_down' });
const token = json(200, TOKEN_BODY);

/** A credential that puts the endpoint in its header and assertion, so the test can tell requests apart. */
function fakeCredential(): ApplicationCredential & { clientAuthentication: jest.Mock<(issuer: string, endpoint: string) => Promise<ClientAuthentication>> } {
  return {
    getAuth: () => null,
    prepareTokenExchangeRequest: async () => ({ subjectToken: 'unused' }),
    clientAuthentication: jest.fn(async (_issuer: string, endpoint: string) => ({
      headers: { 'X-Client-Auth': `header-for:${endpoint}` },
      form: { client_assertion: `assertion-for:${endpoint}`, client_assertion_type: JWT_BEARER },
    })),
  };
}

function decodeJwtPayload(jwt: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString('utf-8'));
}

describe('systemClock.sleep', () => {
  beforeEach(() => {
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  const reason = new Error('cancelled');

  // `listener` is what happens to the abort listener: never added, removed
  // when the timer fires, or added with `once` so the abort removes it.
  // Every case must not leave a timer behind.
  it.each([
    { name: 'resolves after ms without a signal', signal: false, abortBefore: false, abortAtMs: undefined, outcome: 'resolved', atMs: 1000, listener: 'none' },
    { name: 'resolves after ms and removes its abort listener', signal: true, abortBefore: false, abortAtMs: undefined, outcome: 'resolved', atMs: 1000, listener: 'removed' },
    { name: 'rejects at once with the reason of a signal that is already aborted', signal: true, abortBefore: true, abortAtMs: undefined, outcome: 'rejected', atMs: 0, listener: 'none' },
    { name: 'rejects with the reason on abort and clears its timer', signal: true, abortBefore: false, abortAtMs: 400, outcome: 'rejected', atMs: 400, listener: 'once' },
  ])('$name', async ({ signal, abortBefore, abortAtMs, outcome, atMs, listener }) => {
    const controller = new AbortController();
    if (abortBefore) controller.abort(reason);
    const add = jest.spyOn(controller.signal, 'addEventListener');
    const remove = jest.spyOn(controller.signal, 'removeEventListener');

    let elapsed = 0;
    let settled: { outcome: string; value: unknown; atMs: number } | undefined;
    systemClock.sleep(1000, signal ? controller.signal : undefined).then(
      (value) => { settled = { outcome: 'resolved', value, atMs: elapsed }; },
      (value) => { settled = { outcome: 'rejected', value, atMs: elapsed }; },
    );

    await jest.advanceTimersByTimeAsync(0);
    if (abortAtMs !== undefined) {
      elapsed = abortAtMs;
      await jest.advanceTimersByTimeAsync(abortAtMs);
      controller.abort(reason);
      await jest.advanceTimersByTimeAsync(0);
    }
    if (!settled) {
      elapsed = 1000;
      await jest.advanceTimersByTimeAsync(1000 - (abortAtMs ?? 0));
    }

    expect(settled).toEqual({ outcome, value: outcome === 'rejected' ? reason : undefined, atMs });
    expect(jest.getTimerCount()).toBe(0);
    const added = add.mock.calls.map(([type, , options]) => [type, options]);
    const removed = remove.mock.calls.map(([type, fn]) => [type, fn === add.mock.calls[0]?.[1]]);
    expect({ added, removed }).toEqual({
      none: { added: [], removed: [] },
      removed: { added: [['abort', { once: true }]], removed: [['abort', true]] },
      once: { added: [['abort', { once: true }]], removed: [] },
    }[listener]);
  });
});

describe('device authorization grant', () => {
  let originalFetch: typeof fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  describe('requestDeviceAuthorization', () => {
    it('sends the credential headers and form fields, a space-joined scope, and one resource per entry', async () => {
      const credential = fakeCredential();
      const calls = mockFetch({ device: json(200, DEVICE_RESPONSE) });

      await requestDeviceAuthorization(ISSUER, {
        credential,
        scopes: ['openid', 'profile'],
        resources: [RESOURCE_A, RESOURCE_B],
        metadata: METADATA,
      });

      expect(calls).toHaveLength(1);
      expect(calls[0].url).toBe(DEVICE_ENDPOINT);
      expect(calls[0].init.method).toBe('POST');
      expect(calls[0].headers).toEqual({
        'X-Client-Auth': `header-for:${DEVICE_ENDPOINT}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      });
      expect([...calls[0].body.entries()]).toEqual([
        ['scope', 'openid profile'],
        ['resource', RESOURCE_A],
        ['resource', RESOURCE_B],
        ['client_assertion', `assertion-for:${DEVICE_ENDPOINT}`],
        ['client_assertion_type', JWT_BEARER],
      ]);
      expect(credential.clientAuthentication.mock.calls).toEqual([[ISSUER, DEVICE_ENDPOINT]]);
    });

    it('a public client sends client_id in the body and no Authorization header', async () => {
      const calls = mockFetch({ device: json(200, DEVICE_RESPONSE) });

      await requestDeviceAuthorization(ISSUER, { clientId: 'public-client', metadata: METADATA });

      expect(calls[0].headers).toEqual({ 'Content-Type': 'application/x-www-form-urlencoded' });
      expect([...calls[0].body.entries()]).toEqual([['client_id', 'public-client']]);
    });

    it('defaults interval to 5 and sets expiresAt from the clock', async () => {
      const clock = new FakeClock();
      mockFetch({ device: json(200, { ...DEVICE_RESPONSE, interval: undefined, verification_uri_complete: undefined }) });

      const result = await requestDeviceAuthorization(ISSUER, { clientId: 'c', metadata: METADATA, clock });

      expect(result).toStrictEqual({
        deviceCode: 'device-code-1',
        userCode: 'WDJB-MJHT',
        verificationUri: `${ISSUER}/device`,
        expiresIn: 600,
        interval: 5,
        expiresAt: T0 + 600_000,
      });
    });

    it('returns verificationUriComplete and the server interval when present', async () => {
      const clock = new FakeClock();
      mockFetch({ device: json(200, { ...DEVICE_RESPONSE, interval: 7 }) });

      const result = await requestDeviceAuthorization(ISSUER, { clientId: 'c', metadata: METADATA, clock });

      expect(result.verificationUriComplete).toBe(`${ISSUER}/device?user_code=WDJB-MJHT`);
      expect(result.interval).toBe(7);
    });

    it.each(['device_code', 'user_code', 'verification_uri', 'expires_in'])(
      'a response without %s throws DeviceGrantError invalid_response',
      async (field) => {
        mockFetch({ device: json(200, { ...DEVICE_RESPONSE, [field]: undefined }) });

        const error = await requestDeviceAuthorization(ISSUER, { clientId: 'c', metadata: METADATA }).catch((e) => e);

        expect(error).toBeInstanceOf(DeviceGrantError);
        expect(error.errorCode).toBe('invalid_response');
        expect(error.message).toBe(`Device authorization response is missing ${field}`);
      },
    );

    it.each([0, -1, '5', 2.5, null])('a response with interval %p throws DeviceGrantError invalid_response', async (interval) => {
      mockFetch({ device: json(200, { ...DEVICE_RESPONSE, interval }) });

      const error = await requestDeviceAuthorization(ISSUER, { clientId: 'c', metadata: METADATA }).catch((e) => e);

      expect(error).toBeInstanceOf(DeviceGrantError);
      expect(error).toMatchObject({ errorCode: 'invalid_response', status: 200, retryable: true });
      expect(error.message).toBe(`Device authorization response interval ${JSON.stringify(interval)} is not a positive integer`);
    });

    it('metadata without device_authorization_endpoint throws ConfigurationError and sends nothing', async () => {
      const calls = mockFetch({});

      await expect(
        requestDeviceAuthorization(ISSUER, {
          clientId: 'c',
          metadata: { issuer: ISSUER, token_endpoint: TOKEN_ENDPOINT },
        }),
      ).rejects.toThrow(ConfigurationError);
      expect(calls).toHaveLength(0);
    });

    it.each([
      { code: 'invalid_target', status: 400, retryable: true },
      { code: 'invalid_client', status: 401, retryable: false },
    ])('throws DeviceGrantError $code from the device authorization endpoint', async ({ code, status, retryable }) => {
      mockFetch({ device: json(status, { error: code, error_description: `described ${code}` }) });

      const error = await requestDeviceAuthorization(ISSUER, { clientId: 'c', metadata: METADATA }).catch((e) => e);

      expect(error).toBeInstanceOf(DeviceGrantError);
      expect(error).toMatchObject({ errorCode: code, errorDescription: `described ${code}`, status, retryable });
    });

    it('discovers the endpoints when no metadata is supplied', async () => {
      const calls: string[] = [];
      globalThis.fetch = jest.fn(async (input: unknown) => {
        const url = String(input);
        calls.push(url);
        if (url === `${ISSUER}/.well-known/oauth-authorization-server`) return json(200, METADATA)({} as FetchCall);
        return json(200, DEVICE_RESPONSE)({} as FetchCall);
      }) as unknown as typeof fetch;

      await requestDeviceAuthorization(ISSUER, { clientId: 'c' });

      expect(calls).toEqual([`${ISSUER}/.well-known/oauth-authorization-server`, DEVICE_ENDPOINT]);
    });

    it.each([
      { name: 'the default', timeoutMs: undefined, expected: [[10_000]] },
      { name: 'timeoutMs', timeoutMs: 2_500, expected: [[2_500]] },
      { name: 'timeoutMs 0', timeoutMs: 0, expected: [] },
    ])('bounds the request with $name', async ({ timeoutMs, expected }) => {
      const timeout = jest.spyOn(AbortSignal, 'timeout');
      try {
        mockFetch({ device: json(200, DEVICE_RESPONSE) });

        await requestDeviceAuthorization(ISSUER, { clientId: 'c', metadata: METADATA, timeoutMs });

        expect(timeout.mock.calls).toEqual(expected);
      } finally {
        timeout.mockRestore();
      }
    });

    it.each([
      { name: 'a request that does not respond', device: hang },
      { name: 'a 2xx body that stalls', device: stalledBody(200) },
      { name: 'a 400 body that stalls', device: stalledBody(400) },
    ])('throws a retryable DeviceGrantError with the timeout as cause on $name', async ({ device }) => {
      mockFetch({ device });

      const error = await requestDeviceAuthorization(ISSUER, { clientId: 'c', metadata: METADATA, timeoutMs: 5 }).catch((e) => e);

      expect(error).toBeInstanceOf(DeviceGrantError);
      expect(error).toMatchObject({ errorCode: 'invalid_response', retryable: true, status: undefined });
      expect((error.cause as Error).name).toBe('TimeoutError');
    });
  });

  describe('configuration errors before any request', () => {
    const withoutClientAuthentication: ApplicationCredential = {
      getAuth: () => null,
      prepareTokenExchangeRequest: async () => ({ subjectToken: 'unused' }),
    };

    const operations = [
      { name: 'requestDeviceAuthorization', run: (o: object) => requestDeviceAuthorization(ISSUER, o) },
      { name: 'pollDeviceToken', run: (o: object) => pollDeviceToken(ISSUER, { authorization: authorization(), ...o }) },
      { name: 'waitForDeviceToken', run: (o: object) => waitForDeviceToken(ISSUER, { authorization: authorization(), clock: new FakeClock(), ...o }) },
    ];
    const clientOptions = [
      { name: 'both credential and clientId', options: { credential: fakeCredential(), clientId: 'c' } },
      { name: 'neither credential nor clientId', options: {} },
      { name: 'a credential and an empty clientId', options: { credential: fakeCredential(), clientId: '' } },
      { name: 'an empty clientId', options: { clientId: '' } },
      { name: 'a credential without clientAuthentication', options: { credential: withoutClientAuthentication } },
      {
        name: 'a WebIdentity without clientId',
        options: { credential: new WebIdentity({ storageDir: join(tmpdir(), 'device-unused-keys') }) },
      },
    ];
    const cases = operations.flatMap((op) => clientOptions.map((c) => ({ ...c, op })));

    // No metadata is passed, so a check after discovery would show up as a request.
    it.each(cases)('$op.name with $name', async ({ op, options }) => {
      const calls = mockFetch({});

      await expect(op.run(options)).rejects.toThrow(ConfigurationError);
      expect(calls).toHaveLength(0);
    });

    const badEndpoints = ['not a url', 'ftp://zone.example.com/token', '/oauth/2/token'];
    const endpointCases = [
      ...badEndpoints.map((endpoint) => ({
        op: 'requestDeviceAuthorization',
        endpoint,
        run: (metadata: object) => requestDeviceAuthorization(ISSUER, { clientId: 'c', metadata: { ...METADATA, device_authorization_endpoint: endpoint, ...metadata } }),
        field: 'device_authorization_endpoint',
      })),
      ...badEndpoints.map((endpoint) => ({
        op: 'pollDeviceToken',
        endpoint,
        run: (metadata: object) => pollDeviceToken(ISSUER, { clientId: 'c', authorization: authorization(), metadata: { ...METADATA, token_endpoint: endpoint, ...metadata } }),
        field: 'token_endpoint',
      })),
      ...badEndpoints.map((endpoint) => ({
        op: 'waitForDeviceToken',
        endpoint,
        run: (metadata: object) => waitForDeviceToken(ISSUER, { clientId: 'c', authorization: authorization(), clock: new FakeClock(), metadata: { ...METADATA, token_endpoint: endpoint, ...metadata } }),
        field: 'token_endpoint',
      })),
    ];

    // fetch throws TypeError for these URLs. That must not be reported as a retryable network error.
    it.each(endpointCases)('$op with $field $endpoint', async ({ run, endpoint, field }) => {
      const calls = mockFetch({});

      const error = await run({}).catch((e) => e);

      expect(error).toBeInstanceOf(ConfigurationError);
      expect(error.message).toBe(
        `Authorization server "${ISSUER}" advertises a ${field} that is not an http or https URL: ${JSON.stringify(endpoint)}`,
      );
      expect(calls).toHaveLength(0);
    });

    it.each([0, -1, 2.5, '5', undefined])('waitForDeviceToken with a persisted authorization.interval of %p', async (interval) => {
      const calls = mockFetch({});
      const clock = new FakeClock();

      const error = await waitForDeviceToken(ISSUER, {
        clientId: 'c',
        authorization: authorization({ interval: interval as number }),
        metadata: METADATA,
        clock,
      }).catch((e) => e);

      expect(error).toBeInstanceOf(ConfigurationError);
      expect(error.message).toBe(
        `waitForDeviceToken: the device authorization interval ${JSON.stringify(interval)} is not a positive integer`,
      );
      expect(calls).toHaveLength(0);
      expect(clock.waits).toEqual([]);
    });

    it.each([
      { interval: 4, message: 'waitForDeviceToken: interval 4 is below the device authorization interval 5' },
      { interval: 7.5, message: 'waitForDeviceToken: interval 7.5 is not a positive integer' },
      { interval: Number.NaN, message: 'waitForDeviceToken: interval null is not a positive integer' },
      { interval: Number.POSITIVE_INFINITY, message: 'waitForDeviceToken: interval null is not a positive integer' },
      { interval: '7', message: 'waitForDeviceToken: interval "7" is not a positive integer' },
    ])('waitForDeviceToken with an interval of $interval', async ({ interval, message }) => {
      const calls = mockFetch({});
      const clock = new FakeClock();

      const error = await waitForDeviceToken(ISSUER, {
        clientId: 'c',
        authorization: authorization(),
        interval: interval as number,
        clock,
      }).catch((e) => e);

      expect(error).toBeInstanceOf(ConfigurationError);
      expect(error.message).toBe(message);
      expect(calls).toHaveLength(0);
      expect(clock.waits).toEqual([]);
    });
  });

  describe('discovery failures', () => {
    const operations = [
      { name: 'requestDeviceAuthorization', run: (issuer: string, o: object) => requestDeviceAuthorization(issuer, { clientId: 'c', ...o }) },
      { name: 'pollDeviceToken', run: (issuer: string, o: object) => pollDeviceToken(issuer, { clientId: 'c', authorization: authorization(), ...o }) },
      { name: 'waitForDeviceToken', run: (issuer: string, o: object) => waitForDeviceToken(issuer, { clientId: 'c', authorization: authorization(), clock: new FakeClock(), ...o }) },
    ];
    const networkFailure = new TypeError('fetch failed');
    const isHTTPError = (c: unknown) => expect(c).toBeInstanceOf(HTTPError);
    const failures = [
      { name: 'an HTTP 503', discovery: json(503, {}), status: 503, retryable: true, cause: isHTTPError },
      { name: 'an HTTP 429', discovery: json(429, {}), status: 429, retryable: true, cause: isHTTPError },
      { name: 'an HTTP 404', discovery: json(404, {}), status: 404, retryable: false, cause: isHTTPError },
      { name: 'a network error', discovery: () => { throw networkFailure; }, status: undefined, retryable: true, cause: (c: unknown) => expect(c).toBe(networkFailure) },
      { name: 'a timeout while reading the body', discovery: stalledBody(200), status: undefined, retryable: true, cause: (c: unknown) => expect((c as Error).name).toBe('TimeoutError') },
      {
        name: 'a body that is not JSON',
        discovery: () => new Response('not json', { status: 200 }),
        status: undefined,
        retryable: false,
        cause: (c: unknown) => {
          expect(c).toBeInstanceOf(OAuthError);
          expect(c).toMatchObject({ errorCode: 'invalid_response' });
        },
      },
      {
        name: 'an issuer mismatch',
        discovery: json(200, { ...METADATA, issuer: 'https://other.example.com' }),
        status: undefined,
        retryable: false,
        cause: (c: unknown) => {
          expect(c).toBeInstanceOf(OAuthError);
          expect(c).toMatchObject({ errorCode: 'issuer_mismatch' });
        },
      },
    ];
    const cases = operations.flatMap((op) => failures.map((f) => ({ ...f, op })));

    it.each(cases)('$op.name throws DeviceGrantError invalid_response on $name', async ({ op, discovery, status, retryable, cause }) => {
      const calls = mockFetch({ discovery });

      const error = await op.run(ISSUER, { timeoutMs: 5 }).catch((e) => e);

      expect(error).toBeInstanceOf(DeviceGrantError);
      expect(error).toMatchObject({ errorCode: 'invalid_response', status, retryable });
      expect(error.message.startsWith(`Discovery for "${ISSUER}" failed: `)).toBe(true);
      cause(error.cause);
      expect(calls.map((c) => c.url)).toEqual([DISCOVERY_URL]);
    });

    it.each(operations)('$name rejects with the abort reason of a signal aborted before discovery and sends nothing', async ({ run }) => {
      const calls = mockFetch({ discovery: json(200, METADATA) });
      const controller = new AbortController();
      const reason = new Error('cancelled by caller');
      controller.abort(reason);

      await expect(run(ISSUER, { signal: controller.signal })).rejects.toBe(reason);
      expect(calls).toHaveLength(0);
    });

    it.each(operations)('$name rejects with the abort reason when the caller aborts while discovery reads the body', async ({ run }) => {
      const controller = new AbortController();
      const reason = new Error('cancelled by caller');
      const calls = mockFetch({
        discovery: (call) => {
          const response = stalledBody(200)(call);
          controller.abort(reason);
          return response;
        },
      });

      await expect(run(ISSUER, { signal: controller.signal })).rejects.toBe(reason);
      expect(calls.map((c) => c.url)).toEqual([DISCOVERY_URL]);
    });

    it.each(operations)('$name with an issuer that is not an http or https URL throws ConfigurationError and sends nothing', async ({ name, run }) => {
      const calls = mockFetch({});

      const error = await run('not a url', {}).catch((e) => e);

      expect(error).toBeInstanceOf(ConfigurationError);
      expect(error.message).toBe(`${name}: issuer "not a url" is not an http or https URL`);
      expect(calls).toHaveLength(0);
    });
  });

  describe('pollDeviceToken', () => {
    it('discovers the token endpoint when no metadata is supplied', async () => {
      const calls = mockFetch({ discovery: json(200, METADATA), polls: [token] });

      const result = await pollDeviceToken(ISSUER, { clientId: 'c', authorization: authorization() });

      expect(result).toStrictEqual(EXPECTED_TOKEN);
      expect(calls.map((c) => c.url)).toEqual([DISCOVERY_URL, TOKEN_ENDPOINT]);
    });

    it('posts the device code grant with the same client authentication and no resource or scope', async () => {
      const credential = fakeCredential();
      const calls = mockFetch({ polls: [token] });

      const result = await pollDeviceToken(ISSUER, { credential, authorization: authorization(), metadata: METADATA });

      expect(result).toStrictEqual(EXPECTED_TOKEN);
      expect(calls).toHaveLength(1);
      expect(calls[0].url).toBe(TOKEN_ENDPOINT);
      expect(calls[0].headers).toEqual({
        'X-Client-Auth': `header-for:${TOKEN_ENDPOINT}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      });
      expect([...calls[0].body.entries()]).toEqual([
        ['grant_type', DEVICE_GRANT],
        ['device_code', 'device-code-1'],
        ['client_assertion', `assertion-for:${TOKEN_ENDPOINT}`],
        ['client_assertion_type', JWT_BEARER],
      ]);
      expect(credential.clientAuthentication.mock.calls).toEqual([[ISSUER, TOKEN_ENDPOINT]]);
    });

    // The status decides before the code: a 429 or 5xx is retryable even with
    // a permanent code or invalid_grant.
    it.each([
      { status: 400, code: 'authorization_pending', retryable: true },
      { status: 400, code: 'slow_down', retryable: true },
      { status: 400, code: 'invalid_grant', retryable: false },
      ...PERMANENT_ERROR_CODES.map((code) => ({ status: 400, code, retryable: false })),
      { status: 503, code: 'invalid_grant', retryable: true },
      ...PERMANENT_ERROR_CODES.map((code) => ({ status: 503, code, retryable: true })),
      { status: 429, code: 'access_denied', retryable: true },
    ])('throws DeviceGrantError $code on HTTP $status with retryable $retryable', async ({ status, code, retryable }) => {
      mockFetch({ polls: [json(status, { error: code })] });

      const error = await pollDeviceToken(ISSUER, { clientId: 'c', authorization: authorization(), metadata: METADATA }).catch((e) => e);

      expect(error).toBeInstanceOf(DeviceGrantError);
      expect(error).toMatchObject({ errorCode: code, retryable, status });
    });

    it.each([
      { status: 502, retryable: true },
      { status: 429, retryable: true },
      { status: 404, retryable: false },
    ])('throws DeviceGrantError invalid_response for an HTTP $status without an OAuth body', async ({ status, retryable }) => {
      mockFetch({ polls: [() => new Response('not oauth', { status })] });

      const error = await pollDeviceToken(ISSUER, { clientId: 'c', authorization: authorization(), metadata: METADATA }).catch((e) => e);

      expect(error).toBeInstanceOf(DeviceGrantError);
      expect(error).toMatchObject({ errorCode: 'invalid_response', status, retryable, cause: undefined });
      expect(error.message).toBe(`Device token poll failed (HTTP ${status})`);
    });

    const networkFailure = new TypeError('fetch failed');
    it.each([
      { name: 'a network failure', polls: [() => { throw networkFailure; }], cause: (c: unknown) => expect(c).toBe(networkFailure) },
      { name: 'a request timeout', polls: [hang], cause: (c: unknown) => expect((c as Error).name).toBe('TimeoutError') },
      { name: 'a timeout while reading a 2xx body', polls: [stalledBody(200)], cause: (c: unknown) => expect((c as Error).name).toBe('TimeoutError') },
      { name: 'a timeout while reading a 400 body', polls: [stalledBody(400)], cause: (c: unknown) => expect((c as Error).name).toBe('TimeoutError') },
    ])('throws a retryable DeviceGrantError invalid_response with the failure as cause on $name', async ({ polls, cause }) => {
      mockFetch({ polls });

      const error = await pollDeviceToken(ISSUER, { clientId: 'c', authorization: authorization(), metadata: METADATA, timeoutMs: 5 }).catch((e) => e);

      expect(error).toBeInstanceOf(DeviceGrantError);
      expect(error).toMatchObject({ errorCode: 'invalid_response', retryable: true, status: undefined });
      cause(error.cause);
    });

    it('rejects with the abort reason when the caller aborts while the poll is in flight', async () => {
      const controller = new AbortController();
      const reason = new Error('cancelled by caller');
      mockFetch({
        polls: [(call) => {
          const response = hang(call);
          controller.abort(reason);
          return response;
        }],
      });

      await expect(
        pollDeviceToken(ISSUER, { clientId: 'c', authorization: authorization(), metadata: METADATA, signal: controller.signal }),
      ).rejects.toBe(reason);
    });

    it('a token response naming one of two requested resources is returned without a resource', async () => {
      const clock = new FakeClock();
      const calls = mockFetch({
        device: json(200, DEVICE_RESPONSE),
        polls: [json(200, { ...TOKEN_BODY, resource: RESOURCE_A })],
      });

      const auth = await requestDeviceAuthorization(ISSUER, {
        clientId: 'c',
        resources: [RESOURCE_A, RESOURCE_B],
        metadata: METADATA,
        clock,
      });
      const result = await pollDeviceToken(ISSUER, { clientId: 'c', authorization: auth, metadata: METADATA });

      expect(calls[0].body.getAll('resource')).toEqual([RESOURCE_A, RESOURCE_B]);
      expect(calls[1].body.getAll('resource')).toEqual([]);
      expect(result).toStrictEqual(EXPECTED_TOKEN);
    });
  });

  describe('waitForDeviceToken', () => {
    it('polls after each wait and returns the token with refresh_token and id_token as received', async () => {
      const clock = new FakeClock();
      const calls = mockFetch({ polls: [pending, pending, token] });

      const result = await waitForDeviceToken(ISSUER, { clientId: 'c', authorization: authorization(), metadata: METADATA, clock });

      expect(result).toStrictEqual(EXPECTED_TOKEN);
      expect(calls).toHaveLength(3);
      expect(clock.waits).toEqual([5000, 5000, 5000]);
    });

    it.each([
      { name: 'slow_down, then authorization_pending', polls: [slowDown, pending, token], waits: [5000, 10000, 10000] },
      { name: 'slow_down twice', polls: [slowDown, slowDown, token], waits: [5000, 10000, 15000] },
    ])('slow_down adds 5 seconds to this and every later wait: $name', async ({ polls, waits }) => {
      const clock = new FakeClock();
      const calls = mockFetch({ polls });

      await waitForDeviceToken(ISSUER, { clientId: 'c', authorization: authorization(), metadata: METADATA, clock });

      expect(calls).toHaveLength(polls.length);
      expect(clock.waits).toEqual(waits);
    });

    // The loop stops on every OAuth error except authorization_pending and slow_down.
    // `retryable` follows the base spec's permanent-code table, plus invalid_grant on this grant.
    it.each([
      { code: 'access_denied', retryable: false },
      { code: 'expired_token', retryable: false },
      { code: 'invalid_grant', retryable: false },
      { code: 'invalid_client', retryable: false },
      { code: 'invalid_request', retryable: true },
      { code: 'unauthorized_client', retryable: true },
    ])('stops on $code from the server with a DeviceGrantError that has retryable $retryable', async ({ code, retryable }) => {
      const clock = new FakeClock();
      const calls = mockFetch({ polls: [pending, json(400, { error: code }), token] });

      const error = await waitForDeviceToken(ISSUER, { clientId: 'c', authorization: authorization(), metadata: METADATA, clock }).catch((e) => e);

      expect(error).toBeInstanceOf(DeviceGrantError);
      expect(error).toMatchObject({ errorCode: code, retryable, status: 400 });
      expect(calls).toHaveLength(2);
    });

    // expiresAt is 12 seconds after the start.
    it.each([
      { name: 'authorization_pending', polls: [pending, pending, token], calls: 2, waits: [5000, 5000] },
      { name: 'slow_down, which makes the next wait 10 seconds', polls: [slowDown, token], calls: 1, waits: [5000] },
    ])('stops without sending the next poll once it would start after expiresAt: $name', async ({ polls, calls: sent, waits }) => {
      const clock = new FakeClock();
      const calls = mockFetch({ polls });

      const error = await waitForDeviceToken(ISSUER, {
        clientId: 'c',
        authorization: authorization({ expiresIn: 12, expiresAt: T0 + 12_000 }),
        metadata: METADATA,
        clock,
      }).catch((e) => e);

      expect(error).toBeInstanceOf(DeviceGrantError);
      expect(error).toMatchObject({ errorCode: 'expired_token', retryable: false });
      expect(calls).toHaveLength(sent);
      expect(clock.waits).toEqual(waits);
    });

    it('an interval longer than the time left stops without waiting or polling', async () => {
      const clock = new FakeClock();
      const calls = mockFetch({ polls: [token] });

      const error = await waitForDeviceToken(ISSUER, {
        clientId: 'c',
        authorization: authorization({ expiresAt: T0 + 20_000 }),
        interval: 30,
        metadata: METADATA,
        clock,
      }).catch((e) => e);

      expect(error).toBeInstanceOf(DeviceGrantError);
      expect(error.errorCode).toBe('expired_token');
      expect(calls).toHaveLength(0);
      expect(clock.waits).toEqual([]);
    });

    const networkFailure = new TypeError('fetch failed');
    // A network error or a timeout doubles the interval. An HTTP error does not.
    it.each([
      {
        name: 'a network error',
        polls: [() => { throw networkFailure; }],
        interval: 10,
        cause: (c: unknown) => expect(c).toBe(networkFailure),
      },
      {
        name: 'a 5xx without an OAuth body',
        polls: [() => new Response('unavailable', { status: 503 })],
        interval: 5,
        cause: (c: unknown) => {
          expect(c).toBeInstanceOf(DeviceGrantError);
          expect(c).toMatchObject({ errorCode: 'invalid_response', status: 503, retryable: true });
        },
      },
      {
        name: 'a 503 with an OAuth body',
        polls: [json(503, { error: 'temporarily_unavailable' })],
        interval: 5,
        cause: (c: unknown) => {
          expect(c).toBeInstanceOf(DeviceGrantError);
          expect(c).toMatchObject({ errorCode: 'temporarily_unavailable', status: 503, retryable: true });
        },
      },
      {
        name: 'a 503 with a permanent OAuth error code',
        polls: [json(503, { error: 'access_denied' })],
        interval: 5,
        cause: (c: unknown) => {
          expect(c).toBeInstanceOf(DeviceGrantError);
          expect(c).toMatchObject({ errorCode: 'access_denied', status: 503, retryable: true });
        },
      },
      {
        name: 'slow_down, then a network error',
        polls: [slowDown, () => { throw networkFailure; }],
        interval: 20,
        cause: (c: unknown) => expect(c).toBe(networkFailure),
      },
      {
        name: 'a 429',
        polls: [() => new Response('', { status: 429 })],
        interval: 5,
        cause: (c: unknown) => {
          expect(c).toBeInstanceOf(DeviceGrantError);
          expect(c).toMatchObject({ errorCode: 'invalid_response', status: 429, retryable: true });
        },
      },
      {
        name: 'slow_down, then a timeout while reading a 400 body',
        polls: [slowDown, stalledBody(400)],
        interval: 20,
        cause: (c: unknown) => expect((c as Error).name).toBe('TimeoutError'),
      },
      {
        name: 'a timeout while reading a 2xx body',
        polls: [stalledBody(200)],
        interval: 10,
        cause: (c: unknown) => expect((c as Error).name).toBe('TimeoutError'),
      },
    ])('stops on $name with a retryable DevicePollError', async ({ polls, interval, cause }) => {
      const clock = new FakeClock();
      const calls = mockFetch({ polls: [...polls, token] });

      const error = await waitForDeviceToken(ISSUER, { clientId: 'c', authorization: authorization(), metadata: METADATA, clock, timeoutMs: 5 }).catch((e) => e);

      expect(error).toBeInstanceOf(DevicePollError);
      expect(error.retryable).toBe(true);
      expect(error.interval).toBe(interval);
      cause(error.cause);
      expect(calls).toHaveLength(polls.length);
    });

    const credentialFailure = new Error('identity token source unreachable');
    it.each([
      {
        name: 'the credential\'s client authentication fails on the second poll',
        credential: () => {
          const credential = fakeCredential();
          credential.clientAuthentication
            .mockImplementationOnce(async (_issuer, endpoint) => ({ headers: {}, form: { client_assertion: `a:${endpoint}` } }))
            .mockRejectedValueOnce(credentialFailure);
          return { credential };
        },
        polls: [pending],
        check: (e: unknown) => expect(e).toBe(credentialFailure),
      },
      {
        name: 'a 404 without an OAuth body',
        credential: () => ({ clientId: 'c' }),
        polls: [() => new Response('not found', { status: 404 })],
        check: (e: unknown) => {
          expect(e).toBeInstanceOf(DeviceGrantError);
          expect(e).toMatchObject({ errorCode: 'invalid_response', status: 404, retryable: false });
        },
      },
    ])('$name stops and throws the error as is, without interval', async ({ credential, polls, check }) => {
      const clock = new FakeClock();
      const calls = mockFetch({ polls: [...polls, token] });

      const error = await waitForDeviceToken(ISSUER, {
        ...credential(),
        authorization: authorization(),
        metadata: METADATA,
        clock,
      }).catch((e) => e);

      check(error);
      expect(error).not.toBeInstanceOf(DevicePollError);
      expect(error).not.toHaveProperty('interval');
      expect(calls).toHaveLength(polls.length);
    });

    it.each([
      { name: 'without a caller signal', signal: () => undefined },
      { name: 'with a caller deadline longer than the request timeout', signal: () => AbortSignal.timeout(60_000) },
    ])('a poll that exceeds timeoutMs stops the loop with a DevicePollError whose cause is the timeout ($name)', async ({ signal }) => {
      const clock = new FakeClock();
      const calls = mockFetch({ polls: [slowDown, hang] });

      const error = await waitForDeviceToken(ISSUER, {
        clientId: 'c',
        authorization: authorization(),
        metadata: METADATA,
        clock,
        timeoutMs: 5,
        signal: signal(),
      }).catch((e) => e);

      expect(error).toBeInstanceOf(DevicePollError);
      expect(error.retryable).toBe(true);
      expect(error.interval).toBe(20);
      expect((error.cause as Error).name).toBe('TimeoutError');
      expect(calls).toHaveLength(2);
    });

    it('resuming with the interval from a DevicePollError waits that interval first', async () => {
      const clock = new FakeClock();
      mockFetch({ polls: [slowDown, () => { throw networkFailure; }, pending, token] });
      const options = { clientId: 'c', authorization: authorization(), metadata: METADATA, clock };

      const error = await waitForDeviceToken(ISSUER, options).catch((e) => e);
      expect(error).toBeInstanceOf(DevicePollError);
      expect(error.interval).toBe(20);

      await waitForDeviceToken(ISSUER, { ...options, interval: error.interval });

      expect(clock.waits).toEqual([5000, 10000, 20000, 20000]);
    });

    it('aborting during a wait rejects with the abort reason and sends no further request', async () => {
      const clock = new FakeClock();
      const controller = new AbortController();
      const reason = new Error('cancelled by caller');
      clock.onSleep = (n) => {
        if (n === 2) controller.abort(reason);
      };
      const credential = fakeCredential();
      const calls = mockFetch({ polls: [pending, token] });

      await expect(
        waitForDeviceToken(ISSUER, {
          credential,
          authorization: authorization(),
          metadata: METADATA,
          clock,
          signal: controller.signal,
        }),
      ).rejects.toBe(reason);
      expect(calls).toHaveLength(1);
      expect(credential.clientAuthentication).toHaveBeenCalledTimes(1);
    });

    it('aborting while a poll is in flight rejects with the abort reason and sends no further request', async () => {
      const clock = new FakeClock();
      const controller = new AbortController();
      const reason = new Error('cancelled by caller');
      const abortInFlight: Responder = (call) =>
        new Promise((_resolve, reject) => {
          call.init.signal!.addEventListener('abort', () => reject(call.init.signal!.reason));
          controller.abort(reason);
        });
      const calls = mockFetch({ polls: [abortInFlight, token] });

      await expect(
        waitForDeviceToken(ISSUER, {
          clientId: 'c',
          authorization: authorization(),
          metadata: METADATA,
          clock,
          signal: controller.signal,
        }),
      ).rejects.toBe(reason);
      expect(calls).toHaveLength(1);
      expect(clock.waits).toEqual([5000]);
    });

    it('polls with the device code of a DeviceAuthorization built from persisted fields', async () => {
      const clock = new FakeClock();
      const calls = mockFetch({ polls: [token] });
      const persisted = JSON.parse(JSON.stringify(authorization({ deviceCode: 'persisted-code' }))) as DeviceAuthorization;

      await waitForDeviceToken(ISSUER, { clientId: 'c', authorization: persisted, metadata: METADATA, clock });

      expect(calls[0].body.get('device_code')).toBe('persisted-code');
    });
  });

  describe('one flow with a WebIdentity credential', () => {
    let storageDir: string;

    beforeEach(() => {
      storageDir = mkdtempSync(join(tmpdir(), 'device-webidentity-'));
    });

    afterEach(() => {
      rmSync(storageDir, { recursive: true, force: true });
    });

    it('signs each assertion for the endpoint it is sent to, with a new jti every time', async () => {
      const credential = new WebIdentity({ clientId: 'device-client', storageDir, serverName: 'device' });
      const clock = new FakeClock();
      const calls = mockFetch({ device: json(200, DEVICE_RESPONSE), polls: [pending, token] });

      const auth = await requestDeviceAuthorization(ISSUER, { credential, metadata: METADATA, clock });
      const pendingPoll = await pollDeviceToken(ISSUER, { credential, authorization: auth, metadata: METADATA }).catch((e) => e);
      await pollDeviceToken(ISSUER, { credential, authorization: auth, metadata: METADATA });

      expect(pendingPoll).toMatchObject({ errorCode: 'authorization_pending' });

      expect(calls.map((c) => c.url)).toEqual([DEVICE_ENDPOINT, TOKEN_ENDPOINT, TOKEN_ENDPOINT]);
      const claims = calls.map((c) => decodeJwtPayload(c.body.get('client_assertion')!));
      expect(claims.map((c) => c.aud)).toEqual([DEVICE_ENDPOINT, TOKEN_ENDPOINT, TOKEN_ENDPOINT]);
      expect(claims.map((c) => [c.iss, c.sub])).toEqual(Array(3).fill(['device-client', 'device-client']));
      expect(new Set(claims.map((c) => c.jti)).size).toBe(3);
      for (const call of calls) {
        expect(call.body.get('client_assertion_type')).toBe(JWT_BEARER);
        expect(call.body.has('client_id')).toBe(false);
        expect(call.body.has('subject_token_type')).toBe(false);
      }
    });
  });
});
