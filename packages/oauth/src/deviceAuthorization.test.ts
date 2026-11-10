import { jest } from '@jest/globals';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  pollDeviceToken,
  requestDeviceAuthorization,
  type Clock,
  type DeviceAuthorization,
} from './deviceAuthorization.js';
import type { ApplicationCredential, ClientAuthentication } from './credentials.js';
import { ConfigurationError, DeviceGrantError, HTTPError, OAuthError } from './errors.js';
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

/** A clock that reads a fixed time. */
class FakeClock implements Clock {
  time = T0;

  now(): number {
    return this.time;
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

    it('pollDeviceToken without metadata', async () => {
      const calls = mockFetch({});

      const error = await pollDeviceToken(ISSUER, { clientId: 'c', authorization: authorization() } as never).catch((e) => e);

      expect(error).toBeInstanceOf(ConfigurationError);
      expect(error.message).toBe('pollDeviceToken: metadata is required');
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
  });

  describe('discovery failures', () => {
    const operations = [
      { name: 'requestDeviceAuthorization', run: (issuer: string, o: object) => requestDeviceAuthorization(issuer, { clientId: 'c', ...o }) },
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

    it.each([
      { code: 'authorization_pending', retryable: true },
      { code: 'slow_down', retryable: true },
      { code: 'access_denied', retryable: false },
      { code: 'expired_token', retryable: false },
      { code: 'invalid_grant', retryable: false },
      { code: 'invalid_client', retryable: false },
    ])('throws DeviceGrantError $code with retryable $retryable', async ({ code, retryable }) => {
      mockFetch({ polls: [json(400, { error: code })] });

      const error = await pollDeviceToken(ISSUER, { clientId: 'c', authorization: authorization(), metadata: METADATA }).catch((e) => e);

      expect(error).toBeInstanceOf(DeviceGrantError);
      expect(error).toMatchObject({ errorCode: code, retryable, status: 400 });
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
