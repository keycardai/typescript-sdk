import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { inspect } from 'node:util';
import type { ClientAuthentication } from './credentials.js';
import { requestDeviceAuthorization } from './deviceAuthorization.js';
import { ClientSecret } from './server/clientSecret.js';
import { WebIdentity } from './server/webIdentity.js';
import { WorkloadIdentity } from './server/workloadIdentity.js';

const ISSUER = 'https://zone.example.com';
const DEVICE_ENDPOINT = `${ISSUER}/oauth/2/device_authorization`;
const METADATA = { issuer: ISSUER, device_authorization_endpoint: DEVICE_ENDPOINT, token_endpoint: `${ISSUER}/oauth/2/token` };

// Each case builds a value the way the SDK returns it and lists the secret
// values in it. util.inspect is what console.log uses. breakLength keeps the
// expected strings on one line.
describe('printed forms leave out secrets', () => {
  let tmp: string;
  let originalFetch: typeof fetch;

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'printed-'));
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true });
    globalThis.fetch = originalFetch;
  });

  it.each([
    {
      name: 'ClientSecret client authentication',
      build: () => new ClientSecret('client-id', 'client-secret').clientAuthentication(ISSUER, DEVICE_ENDPOINT),
      secrets: (v: ClientAuthentication): string[] => [v.headers.Authorization, 'client-secret'],
      want: "ClientAuthentication { headers: [ 'Authorization' ], form: [] }",
    },
    {
      name: 'WebIdentity client authentication',
      build: () =>
        new WebIdentity({ clientId: 'client-id', storageDir: join(tmp, 'keys') }).clientAuthentication(ISSUER, DEVICE_ENDPOINT),
      secrets: (v: ClientAuthentication): string[] => [v.form.client_assertion],
      want: "ClientAuthentication { headers: [], form: [ 'client_assertion', 'client_assertion_type' ] }",
    },
    {
      name: 'WorkloadIdentity client authentication',
      build: () =>
        new WorkloadIdentity(async () => 'assertion-jwt', { clientId: 'client-id' }).clientAuthentication(ISSUER, DEVICE_ENDPOINT),
      secrets: (): string[] => ['assertion-jwt'],
      want: "ClientAuthentication { headers: [], form: [ 'client_assertion', 'client_assertion_type', 'client_id' ] }",
    },
    {
      name: 'DeviceAuthorization',
      build: () => {
        globalThis.fetch = (async () =>
          new Response(
            JSON.stringify({
              device_code: 'device-code',
              user_code: 'WDJB-MJHT',
              verification_uri: `${ISSUER}/device`,
              verification_uri_complete: `${ISSUER}/device?user_code=WDJB-MJHT`,
              expires_in: 600,
              interval: 5,
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          )) as typeof fetch;
        return requestDeviceAuthorization(ISSUER, {
          clientId: 'public-client',
          metadata: METADATA,
          clock: { now: () => Date.UTC(2026, 0, 1), sleep: async () => {} },
        });
      },
      secrets: (): string[] => ['device-code'],
      want:
        "DeviceAuthorization { userCode: 'WDJB-MJHT', verificationUri: 'https://zone.example.com/device', " +
        "expiresIn: 600, interval: 5, expiresAt: 1767226200000, " +
        "verificationUriComplete: 'https://zone.example.com/device?user_code=WDJB-MJHT' }",
    },
  ])('$name', async ({ build, secrets, want }) => {
    const value = await build();
    const outputs = [
      inspect(value, { breakLength: Infinity }),
      inspect({ nested: value }, { breakLength: Infinity }),
    ];

    expect(outputs).toEqual([want, `{ nested: ${want} }`]);
    for (const secret of secrets(value)) {
      expect(secret).toBeTruthy();
      for (const output of outputs) expect(output).not.toContain(secret);
    }
  });

  it('JSON keeps deviceCode, so a persisted DeviceAuthorization can poll', async () => {
    globalThis.fetch = (async () =>
      new Response(
        JSON.stringify({ device_code: 'device-code', user_code: 'U', verification_uri: `${ISSUER}/device`, expires_in: 600 }),
        { status: 200 },
      )) as typeof fetch;

    const value = await requestDeviceAuthorization(ISSUER, { clientId: 'public-client', metadata: METADATA });

    expect(JSON.parse(JSON.stringify(value))).toMatchObject({ deviceCode: 'device-code' });
  });
});
