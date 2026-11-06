import { jest } from '@jest/globals';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  pollDeviceToken,
  requestDeviceAuthorization,
  waitForDeviceToken,
  type Clock,
  type DeviceAuthorization,
} from './deviceAuthorization.js';
import type { ApplicationCredential, ClientAuthentication } from './credentials.js';
import { ConfigurationError, DeviceGrantError, DevicePollError, HTTPError } from './errors.js';
import { WebIdentity } from './server/webIdentity.js';

const ISSUER = 'https://zone.example.com';
const DEVICE_ENDPOINT = `${ISSUER}/oauth/2/device_authorization`;
const TOKEN_ENDPOINT = `${ISSUER}/oauth/2/token`;
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

/** Routes the device endpoint to `device` and each token endpoint call to the next entry of `polls`. */
function mockFetch(routes: { device?: Responder; polls?: Responder[] }): FetchCall[] {
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

const pending = json(400, { error: 'authorization_pending' });
const slowDown = json(400, { error: 'slow_down' });
const token = json(200, TOKEN_BODY);

/** A credential whose client authentication names the endpoint, so each request is identifiable. */
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
    it('row 1: sends the credential headers and form fields, a space-joined scope, and one resource per entry', async () => {
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

    it('row 2: a public client sends client_id in the body and no Authorization header', async () => {
      const calls = mockFetch({ device: json(200, DEVICE_RESPONSE) });

      await requestDeviceAuthorization(ISSUER, { clientId: 'public-client', metadata: METADATA });

      expect(calls[0].headers).toEqual({ 'Content-Type': 'application/x-www-form-urlencoded' });
      expect([...calls[0].body.entries()]).toEqual([['client_id', 'public-client']]);
    });

    it('row 5: defaults interval to 5 and sets expiresAt from the clock', async () => {
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
      'row 6: a response without %s throws DeviceGrantError invalid_response',
      async (field) => {
        mockFetch({ device: json(200, { ...DEVICE_RESPONSE, [field]: undefined }) });

        const error = await requestDeviceAuthorization(ISSUER, { clientId: 'c', metadata: METADATA }).catch((e) => e);

        expect(error).toBeInstanceOf(DeviceGrantError);
        expect(error.errorCode).toBe('invalid_response');
        expect(error.message).toBe(`Device authorization response is missing ${field}`);
      },
    );

    it('row 4: metadata without device_authorization_endpoint throws ConfigurationError and sends nothing', async () => {
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
      { label: 'row 3', name: 'both credential and clientId', options: { credential: fakeCredential(), clientId: 'c' } },
      { label: 'row 3', name: 'neither credential nor clientId', options: {} },
      { label: 'row 23', name: 'a credential without clientAuthentication', options: { credential: withoutClientAuthentication } },
      {
        label: 'WebIdentity row 8',
        name: 'a WebIdentity without clientId',
        options: { credential: new WebIdentity({ storageDir: join(tmpdir(), 'device-unused-keys') }) },
      },
    ];
    const cases = operations.flatMap((op) => clientOptions.map((c) => ({ ...c, op })));

    // No metadata is passed, so a check after discovery would show up as a request.
    it.each(cases)('$label: $op.name with $name', async ({ op, options }) => {
      const calls = mockFetch({});

      await expect(op.run(options)).rejects.toThrow(ConfigurationError);
      expect(calls).toHaveLength(0);
    });

    it('row 19: waitForDeviceToken with an interval below authorization.interval', async () => {
      const calls = mockFetch({});
      const clock = new FakeClock();

      await expect(
        waitForDeviceToken(ISSUER, { clientId: 'c', authorization: authorization(), interval: 4, clock }),
      ).rejects.toThrow(ConfigurationError);
      expect(calls).toHaveLength(0);
      expect(clock.waits).toEqual([]);
    });
  });

  describe('pollDeviceToken', () => {
    it('row 7: posts the device code grant with the same client authentication and no resource or scope', async () => {
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

    it('throws HTTPError for a non-OAuth error response', async () => {
      mockFetch({ polls: [() => new Response('bad gateway', { status: 502 })] });

      const error = await pollDeviceToken(ISSUER, { clientId: 'c', authorization: authorization(), metadata: METADATA }).catch((e) => e);

      expect(error).toBeInstanceOf(HTTPError);
      expect(error.status).toBe(502);
    });

    it('throws the fetch error unchanged on a network failure', async () => {
      const failure = new TypeError('fetch failed');
      mockFetch({ polls: [() => { throw failure; }] });

      await expect(
        pollDeviceToken(ISSUER, { clientId: 'c', authorization: authorization(), metadata: METADATA }),
      ).rejects.toBe(failure);
    });
  });

  describe('waitForDeviceToken', () => {
    it('row 8: polls after each wait and returns the token with refresh_token and id_token as received', async () => {
      const clock = new FakeClock();
      const calls = mockFetch({ polls: [pending, pending, token] });

      const result = await waitForDeviceToken(ISSUER, { clientId: 'c', authorization: authorization(), metadata: METADATA, clock });

      expect(result).toStrictEqual(EXPECTED_TOKEN);
      expect(calls).toHaveLength(3);
      expect(clock.waits).toEqual([5000, 5000, 5000]);
    });

    it('row 9: slow_down adds 5 seconds to this and every later wait', async () => {
      const clock = new FakeClock();
      const calls = mockFetch({ polls: [slowDown, pending, token] });

      await waitForDeviceToken(ISSUER, { clientId: 'c', authorization: authorization(), metadata: METADATA, clock });

      expect(calls).toHaveLength(3);
      expect(clock.waits).toEqual([5000, 10000, 10000]);
    });

    it.each([
      { row: 10, code: 'access_denied' },
      { row: 12, code: 'expired_token' },
      { row: 12, code: 'invalid_grant' },
    ])('row $row: stops on $code from the server with a non-retryable DeviceGrantError', async ({ code }) => {
      const clock = new FakeClock();
      const calls = mockFetch({ polls: [pending, json(400, { error: code })] });

      const error = await waitForDeviceToken(ISSUER, { clientId: 'c', authorization: authorization(), metadata: METADATA, clock }).catch((e) => e);

      expect(error).toBeInstanceOf(DeviceGrantError);
      expect(error).toMatchObject({ errorCode: code, retryable: false });
      expect(calls).toHaveLength(2);
    });

    it('row 11: stops without sending the next poll once it would start after expiresAt', async () => {
      const clock = new FakeClock();
      const calls = mockFetch({ polls: [pending, pending, token] });

      const error = await waitForDeviceToken(ISSUER, {
        clientId: 'c',
        authorization: authorization({ expiresIn: 12, expiresAt: T0 + 12_000 }),
        metadata: METADATA,
        clock,
      }).catch((e) => e);

      expect(error).toBeInstanceOf(DeviceGrantError);
      expect(error).toMatchObject({ errorCode: 'expired_token', retryable: false });
      expect(calls).toHaveLength(2);
      expect(clock.waits).toEqual([5000, 5000]);
    });

    it('row 21: an interval longer than the time left stops without waiting or polling', async () => {
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
    it.each([
      {
        row: 13,
        name: 'a network error',
        polls: [() => { throw networkFailure; }],
        interval: 5,
        cause: (c: unknown) => expect(c).toBe(networkFailure),
      },
      {
        row: 13,
        name: 'a 5xx without an OAuth body',
        polls: [() => new Response('unavailable', { status: 503 })],
        interval: 5,
        cause: (c: unknown) => {
          expect(c).toBeInstanceOf(HTTPError);
          expect((c as HTTPError).status).toBe(503);
        },
      },
      {
        row: 13,
        name: 'a 5xx with an OAuth body',
        polls: [json(503, { error: 'temporarily_unavailable' })],
        interval: 5,
        cause: (c: unknown) => {
          expect(c).toBeInstanceOf(DeviceGrantError);
          expect(c).toMatchObject({ errorCode: 'temporarily_unavailable', status: 503 });
        },
      },
      {
        row: 16,
        name: 'slow_down, then a network error',
        polls: [slowDown, () => { throw networkFailure; }],
        interval: 10,
        cause: (c: unknown) => expect(c).toBe(networkFailure),
      },
      {
        row: 17,
        name: 'a 429',
        polls: [() => new Response('', { status: 429 })],
        interval: 5,
        cause: (c: unknown) => {
          expect(c).toBeInstanceOf(HTTPError);
          expect((c as HTTPError).status).toBe(429);
        },
      },
    ])('row $row: stops on $name with a retryable DevicePollError', async ({ polls, interval, cause }) => {
      const clock = new FakeClock();
      const calls = mockFetch({ polls: [...polls, token] });

      const error = await waitForDeviceToken(ISSUER, { clientId: 'c', authorization: authorization(), metadata: METADATA, clock }).catch((e) => e);

      expect(error).toBeInstanceOf(DevicePollError);
      expect(error.retryable).toBe(true);
      expect(error.interval).toBe(interval);
      cause(error.cause);
      expect(calls).toHaveLength(polls.length);
    });

    it('a poll that exceeds timeoutMs stops the loop with a DevicePollError whose cause is the timeout', async () => {
      const clock = new FakeClock();
      const hang: Responder = (call) =>
        new Promise((_resolve, reject) => {
          call.init.signal!.addEventListener('abort', () => reject(call.init.signal!.reason));
        });
      const calls = mockFetch({ polls: [hang] });

      const error = await waitForDeviceToken(ISSUER, {
        clientId: 'c',
        authorization: authorization(),
        metadata: METADATA,
        clock,
        timeoutMs: 5,
      }).catch((e) => e);

      expect(error).toBeInstanceOf(DevicePollError);
      expect((error.cause as Error).name).toBe('TimeoutError');
      expect(calls).toHaveLength(1);
    });

    it('row 18: resuming with the interval from a DevicePollError waits that interval first', async () => {
      const clock = new FakeClock();
      mockFetch({ polls: [pending, token] });

      await waitForDeviceToken(ISSUER, { clientId: 'c', authorization: authorization(), interval: 10, metadata: METADATA, clock });

      expect(clock.waits).toEqual([10000, 10000]);
    });

    it('row 14: aborting during a wait rejects with the abort reason and sends no further request', async () => {
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

    it('row 20: aborting while a poll is in flight rejects with the abort reason and sends no further request', async () => {
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

    it('row 15: polls with the device code of a DeviceAuthorization built from persisted fields', async () => {
      const clock = new FakeClock();
      const calls = mockFetch({ polls: [token] });
      const persisted = JSON.parse(JSON.stringify(authorization({ deviceCode: 'persisted-code' }))) as DeviceAuthorization;

      await waitForDeviceToken(ISSUER, { clientId: 'c', authorization: persisted, metadata: METADATA, clock });

      expect(calls[0].body.get('device_code')).toBe('persisted-code');
    });

    it('row 24: a token response naming one of two requested resources is returned without a resource', async () => {
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
      const result = await waitForDeviceToken(ISSUER, { clientId: 'c', authorization: auth, metadata: METADATA, clock });

      expect(calls[0].body.getAll('resource')).toEqual([RESOURCE_A, RESOURCE_B]);
      expect(calls[1].body.getAll('resource')).toEqual([]);
      expect(result).toStrictEqual(EXPECTED_TOKEN);
    });
  });

  describe('row 22: one flow with a WebIdentity credential', () => {
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
      await waitForDeviceToken(ISSUER, { credential, authorization: auth, metadata: METADATA, clock });

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
