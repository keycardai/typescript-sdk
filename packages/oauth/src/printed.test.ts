import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { inspect } from 'node:util';
import { requestDeviceAuthorization } from './deviceAuthorization.js';
import { JWTSigner } from './jwt/signer.js';
import { generatePkcePair } from './pkce.js';
import { registerClient } from './registration.js';
import { ClientSecret } from './server/clientSecret.js';
import { TokenVerifier } from './server/tokenVerifier.js';
import { WebIdentity } from './server/webIdentity.js';
import { WorkloadIdentity } from './server/workloadIdentity.js';
import { deserializeTokenResponse } from './tokenExchange.js';
import { beginAuthorization } from './webApp.js';

const ISSUER = 'https://zone.example.com';
const DEVICE_ENDPOINT = `${ISSUER}/oauth/2/device_authorization`;
const REGISTRATION_ENDPOINT = `${ISSUER}/oauth/2/register`;
const RESOURCE = 'https://api.example.com';
const ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';
const METADATA = {
  issuer: ISSUER,
  authorization_endpoint: `${ISSUER}/oauth/2/authorize`,
  device_authorization_endpoint: DEVICE_ENDPOINT,
  token_endpoint: `${ISSUER}/oauth/2/token`,
  registration_endpoint: REGISTRATION_ENDPOINT,
};

/** Answers every request with `body`, and discovery with METADATA. */
function respondWith(body: unknown, status = 200): void {
  globalThis.fetch = (async (input: unknown) => {
    const json = String(input).endsWith('/.well-known/oauth-authorization-server') ? METADATA : body;
    return new Response(JSON.stringify(json), { status: json === METADATA ? 200 : status });
  }) as typeof fetch;
}

/** A token for `TokenVerifier`, signed with a new key, and the keyring that verifies it. */
async function signedToken(): Promise<{ token: string; verifier: TokenVerifier }> {
  const pair = await crypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['sign', 'verify'],
  );
  const signer = new JWTSigner({ key: async () => ({ key: pair.privateKey, kid: 'kid-1', issuer: ISSUER }) });
  const token = await signer.sign({
    iss: ISSUER,
    sub: 'user-1',
    client_id: 'service-x',
    scope: 'read',
    iat: 1_700_000_000,
    exp: 4_102_444_800,
    aud: RESOURCE,
  });
  const verifier = new TokenVerifier({ issuer: ISSUER, keyring: { key: async () => pair.publicKey }, audience: RESOURCE });
  return { token, verifier };
}

// Each case builds a value the way the SDK returns it and names the secret
// values in it. util.inspect is what console.log uses. breakLength keeps the
// expected strings on one line. `want` is a function of the value for the
// fields that are random, such as a PKCE challenge.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Built = any;

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

  it.each<{ name: string; build: () => Promise<Built>; secrets: (v: Built) => string[]; want: (v: Built) => string }>([
    {
      name: 'ClientSecret client authentication',
      build: () => new ClientSecret('client-id', 'client-secret').clientAuthentication(ISSUER, DEVICE_ENDPOINT),
      secrets: (v) => [v.headers.Authorization, 'client-secret'],
      want: () => "ClientAuthentication { headers: [ 'Authorization' ], form: [] }",
    },
    {
      name: 'WebIdentity client authentication',
      build: () =>
        new WebIdentity({ clientId: 'client-id', storageDir: join(tmp, 'keys') }).clientAuthentication(ISSUER, DEVICE_ENDPOINT),
      secrets: (v) => [v.form.client_assertion],
      want: () => "ClientAuthentication { headers: [], form: [ 'client_assertion', 'client_assertion_type' ] }",
    },
    {
      name: 'WorkloadIdentity client authentication',
      build: () =>
        new WorkloadIdentity(async () => 'assertion-jwt', { clientId: 'client-id' }).clientAuthentication(ISSUER, DEVICE_ENDPOINT),
      secrets: () => ['assertion-jwt'],
      want: () => "ClientAuthentication { headers: [], form: [ 'client_assertion', 'client_assertion_type', 'client_id' ] }",
    },
    {
      name: 'DeviceAuthorization',
      build: () => {
        respondWith({
          device_code: 'device-code',
          user_code: 'WDJB-MJHT',
          verification_uri: `${ISSUER}/device`,
          verification_uri_complete: `${ISSUER}/device?user_code=WDJB-MJHT`,
          expires_in: 600,
          interval: 5,
        });
        return requestDeviceAuthorization(ISSUER, {
          clientId: 'public-client',
          metadata: METADATA,
          clock: { now: () => Date.UTC(2026, 0, 1), sleep: async () => {} },
        });
      },
      secrets: () => ['device-code'],
      want: () =>
        "DeviceAuthorization { userCode: 'WDJB-MJHT', verificationUri: 'https://zone.example.com/device', " +
        "expiresIn: 600, interval: 5, expiresAt: 1767226200000, " +
        "verificationUriComplete: 'https://zone.example.com/device?user_code=WDJB-MJHT' }",
    },
    {
      name: 'TokenResponse',
      build: async () =>
        deserializeTokenResponse({
          access_token: 'access-token',
          token_type: 'Bearer',
          expires_in: 3600,
          refresh_token: 'refresh-token',
          id_token: 'id-token',
          scope: 'openid profile',
        }),
      secrets: () => ['access-token', 'refresh-token', 'id-token'],
      want: () => "TokenResponse { tokenType: 'Bearer', expiresIn: 3600, scope: [ 'openid', 'profile' ] }",
    },
    {
      name: 'AccessToken from TokenVerifier',
      build: async () => {
        const { token, verifier } = await signedToken();
        return verifier.verifyToken(token);
      },
      secrets: (v) => [v.token],
      want: () =>
        "AccessToken { clientId: 'service-x', scopes: [ 'read' ], expiresAt: 4102444800, resource: undefined, " +
        "sub: 'user-1', subProfile: undefined, keycardAppId: undefined }",
    },
    {
      name: 'ClientSecret getAuth',
      build: async () => new ClientSecret('client-id', 'client-secret').getAuth(),
      secrets: () => ['client-secret'],
      want: () => "ClientAuth { clientId: 'client-id' }",
    },
    {
      name: 'ClientSecret token exchange request',
      build: () => new ClientSecret('client-id', 'client-secret').prepareTokenExchangeRequest('subject-token', RESOURCE),
      secrets: () => ['subject-token'],
      want: () => `TokenExchangeRequest { resource: '${RESOURCE}', subjectTokenType: '${ACCESS_TOKEN_TYPE}' }`,
    },
    {
      name: 'WorkloadIdentity token exchange request',
      build: () =>
        new WorkloadIdentity(async () => 'assertion-jwt', { clientId: 'client-id' }).prepareTokenExchangeRequest(
          'subject-token',
          RESOURCE,
        ),
      secrets: () => ['subject-token', 'assertion-jwt'],
      want: () =>
        `TokenExchangeRequest { resource: '${RESOURCE}', subjectTokenType: '${ACCESS_TOKEN_TYPE}', ` +
        "clientAssertionType: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', clientId: 'client-id' }",
    },
    {
      name: 'Pkce',
      build: () => generatePkcePair(),
      secrets: (v) => [v.codeVerifier],
      want: (v) => `Pkce { codeChallenge: '${v.codeChallenge}', codeChallengeMethod: 'S256' }`,
    },
    {
      name: 'AuthorizationRedirect',
      build: () =>
        beginAuthorization(ISSUER, { clientId: 'client-id', redirectUri: 'https://app.example.com/callback', metadata: METADATA }),
      secrets: (v) => [v.codeVerifier],
      want: (v) => `AuthorizationRedirect { url: '${v.url}', state: '${v.state}', resources: [] }`,
    },
    {
      name: 'ClientRegistrationResponse',
      build: () => {
        respondWith(
          {
            client_id: 'client-id',
            client_secret: 'client-secret',
            registration_access_token: 'registration-token',
            client_name: 'svc',
          },
          201,
        );
        return registerClient(ISSUER, { clientName: 'svc' });
      },
      secrets: () => ['client-secret', 'registration-token'],
      want: () =>
        "ClientRegistrationResponse { clientId: 'client-id', clientName: 'svc', redirectUris: undefined, " +
        "grantTypes: undefined, responseTypes: undefined, scope: undefined, raw: { client_id: 'client-id', client_name: 'svc' } }",
    },
  ])('$name', async ({ build, secrets, want }) => {
    const value = await build();
    const outputs = [
      inspect(value, { breakLength: Infinity }),
      inspect({ nested: value }, { breakLength: Infinity }),
    ];

    expect(outputs).toEqual([want(value), `{ nested: ${want(value)} }`]);
    for (const secret of secrets(value)) {
      expect(secret).toBeTruthy();
      for (const output of outputs) expect(output).not.toContain(secret);
    }
  });

  it('JSON keeps every field, so persisted values can be used again', async () => {
    respondWith({ device_code: 'device-code', user_code: 'U', verification_uri: `${ISSUER}/device`, expires_in: 600 });
    const device = await requestDeviceAuthorization(ISSUER, { clientId: 'public-client', metadata: METADATA });
    const token = deserializeTokenResponse({ access_token: 'access-token', refresh_token: 'refresh-token' });

    expect(JSON.parse(JSON.stringify(device))).toMatchObject({ deviceCode: 'device-code' });
    expect(JSON.parse(JSON.stringify(token))).toMatchObject({ accessToken: 'access-token', refreshToken: 'refresh-token' });
  });
});
