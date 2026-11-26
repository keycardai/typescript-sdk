import { jest } from '@jest/globals';
import { inspect } from 'node:util';
import express from 'express';
import request from 'supertest';
import { requireBearerAuth, subdomainZoneResolver, type AuthenticatedRequest } from './bearerAuth.js';
import { createKeycardMiddleware } from './middleware.js';
import { TokenVerifier } from '@keycardai/oauth/server';
import type { AccessToken } from '@keycardai/oauth/server';
import { ConfigurationError, InvalidTokenError, JWKSKeyNotFoundError } from '@keycardai/oauth/errors';
import { JWTVerifier } from '@keycardai/oauth/jwt/verifier';
import { JWKSOAuthKeyring, JWTSigner, type PrivateKeyring } from '@keycardai/oauth';

const VALID_TOKEN: AccessToken = {
  token: 'valid-jwt',
  clientId: 'svc-x',
  scopes: ['read', 'write'],
  expiresAt: Math.floor(Date.now() / 1000) + 3600,
};

function makeVerifier(result: AccessToken | null) {
  const verifier = {
    verifyToken: jest.fn<() => Promise<AccessToken | null>>().mockResolvedValue(result),
    verifyTokenForZone: jest.fn(),
    clearCache: jest.fn(),
  } as unknown as TokenVerifier;
  return verifier;
}

function makeThrowingVerifier(error: Error) {
  const verifier = {
    verifyToken: jest.fn<() => Promise<AccessToken | null>>().mockRejectedValue(error),
    verifyTokenForZone: jest.fn(),
    clearCache: jest.fn(),
  } as unknown as TokenVerifier;
  return verifier;
}

function makeApp(verifier: TokenVerifier, requiredScopes?: string[]) {
  const app = express();
  app.use(requireBearerAuth({ verifier, requiredScopes }));
  app.get('/resource', (req, res) => {
    res.json({ clientId: (req as any).auth.clientId });
  });
  return app;
}

describe('requireBearerAuth', () => {
  it('sets req.auth and calls next on a valid token', async () => {
    const app = makeApp(makeVerifier(VALID_TOKEN));
    const res = await request(app)
      .get('/resource')
      .set('Authorization', 'Bearer valid-jwt');
    expect(res.status).toBe(200);
    expect(res.body.clientId).toBe('svc-x');
  });

  function makeIdentityApp(verifier: TokenVerifier) {
    const app = express();
    app.use(requireBearerAuth({ verifier }));
    app.get('/whoami', (req, res) => {
      const { clientId, sub, subProfile, keycardAppId } = (req as any).auth as AccessToken;
      res.json({ clientId, sub, subProfile, keycardAppId });
    });
    return app;
  }

  it('exposes the caller identity claims on req.auth for a Keycard token', async () => {
    const keycardToken: AccessToken = {
      ...VALID_TOKEN,
      clientId: 'cred-123',
      sub: 'alice@example.com',
      subProfile: 'user',
      keycardAppId: 'app-456',
    };
    const res = await request(makeIdentityApp(makeVerifier(keycardToken)))
      .get('/whoami')
      .set('Authorization', 'Bearer valid-jwt');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      clientId: 'cred-123',
      sub: 'alice@example.com',
      subProfile: 'user',
      keycardAppId: 'app-456',
    });
  });

  it('leaves the Keycard identity claims undefined on req.auth when the token lacks them', async () => {
    const res = await request(makeIdentityApp(makeVerifier(VALID_TOKEN)))
      .get('/whoami')
      .set('Authorization', 'Bearer valid-jwt');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ clientId: 'svc-x' });
    expect(res.body.sub).toBeUndefined();
    expect(res.body.subProfile).toBeUndefined();
    expect(res.body.keycardAppId).toBeUndefined();
  });

  it('returns 401 with a resource_metadata URL in WWW-Authenticate when no Authorization header', async () => {
    const app = makeApp(makeVerifier(VALID_TOKEN));
    const res = await request(app).get('/resource');
    expect(res.status).toBe(401);
    const wwwAuth = res.headers['www-authenticate'] as string;
    expect(wwwAuth).toMatch(/resource_metadata="http:\/\/127\.0\.0\.1(:\d+)?\/\.well-known\/oauth-protected-resource"/);
  });

  it('returns 401 when verifier returns null (invalid token)', async () => {
    const app = makeApp(makeVerifier(null));
    const res = await request(app)
      .get('/resource')
      .set('Authorization', 'Bearer bad-jwt');
    expect(res.status).toBe(401);
    expect(res.headers['www-authenticate']).toMatch(/error=/);
  });

  it('returns 400 on malformed Authorization header', async () => {
    const app = makeApp(makeVerifier(VALID_TOKEN));
    const res = await request(app)
      .get('/resource')
      .set('Authorization', 'Bearer');
    expect(res.status).toBe(400);
  });

  it('returns 401 on non-Bearer scheme', async () => {
    const app = makeApp(makeVerifier(VALID_TOKEN));
    const res = await request(app)
      .get('/resource')
      .set('Authorization', 'Basic abc123');
    expect(res.status).toBe(401);
  });

  it('returns 403 when required scopes are missing', async () => {
    const tokenWithoutAdmin: AccessToken = { ...VALID_TOKEN, scopes: ['read'] };
    const app = makeApp(makeVerifier(tokenWithoutAdmin), ['admin']);
    const res = await request(app)
      .get('/resource')
      .set('Authorization', 'Bearer valid-jwt');
    expect(res.status).toBe(403);
    expect(res.headers['www-authenticate']).toMatch(/insufficient_scope/);
  });

  it('returns 401 when token resource audience does not match request origin', async () => {
    const tokenForOtherService: AccessToken = {
      ...VALID_TOKEN,
      resource: 'https://other-service.example.com',
    };
    const app = makeApp(makeVerifier(tokenForOtherService));
    const res = await request(app)
      .get('/resource')
      .set('Authorization', 'Bearer valid-jwt');
    expect(res.status).toBe(401);
    expect(res.headers['www-authenticate']).toMatch(/error="invalid_token"/);
  });

  describe('URN resource', () => {
    const URN = 'urn:openshell-claude-sandbox';
    const tokenForUrn: AccessToken = { ...VALID_TOKEN, resource: URN };

    // Restore only these spies: other describes in this file hold spies
    // (globalThis.fetch) created at collection time.
    const spies: Array<{ mockRestore(): void }> = [];
    afterEach(() => {
      spies.splice(0).forEach((spy) => spy.mockRestore());
    });

    function makeAudienceApp(audience: string | readonly string[], zoneResolver?: () => string | undefined) {
      spies.push(
        jest.spyOn(console, 'warn').mockImplementation(() => {}),
        jest.spyOn(TokenVerifier.prototype, 'verifyToken').mockResolvedValue(tokenForUrn),
        jest.spyOn(TokenVerifier.prototype, 'verifyTokenForZone').mockResolvedValue(tokenForUrn),
      );
      const app = express();
      app.use(requireBearerAuth({ zoneUrl: 'https://zone.keycard.cloud', audience, zoneResolver }));
      app.get('/resource', (_req, res) => res.json({ ok: true }));
      return app;
    }

    it('accepts a URN resource that matches the configured audience', async () => {
      const res = await request(makeAudienceApp(URN))
        .get('/resource')
        .set('Authorization', 'Bearer valid-jwt');
      expect(res.status).toBe(200);
    });

    it('accepts a URN resource that matches the second configured audience', async () => {
      const res = await request(makeAudienceApp(['urn:other-service', URN]))
        .get('/resource')
        .set('Authorization', 'Bearer valid-jwt');
      expect(res.status).toBe(200);
    });

    it('accepts a URN resource that matches the configured audience on a zone-resolved request', async () => {
      const res = await request(makeAudienceApp(URN, () => 'zone-a'))
        .get('/resource')
        .set('Authorization', 'Bearer valid-jwt');
      expect(res.status).toBe(200);
    });

    it('rejects a URN resource that is not the configured audience', async () => {
      const res = await request(makeAudienceApp('urn:some-other-service'))
        .get('/resource')
        .set('Authorization', 'Bearer valid-jwt');
      expect(res.status).toBe(401);
      expect(res.headers['www-authenticate']).toMatch(/Token not intended for resource/);
    });

    it('rejects a URN resource when the middleware has no audience (caller-supplied verifier)', async () => {
      const res = await request(makeApp(makeVerifier(tokenForUrn)))
        .get('/resource')
        .set('Authorization', 'Bearer valid-jwt');
      expect(res.status).toBe(401);
      expect(res.headers['www-authenticate']).toMatch(/Token not intended for resource/);
    });
  });

  it('accepts a token with no resource claim (audience not enforced by token)', async () => {
    const tokenNoResource: AccessToken = { ...VALID_TOKEN, resource: undefined };
    const app = makeApp(makeVerifier(tokenNoResource));
    const res = await request(app)
      .get('/resource')
      .set('Authorization', 'Bearer valid-jwt');
    expect(res.status).toBe(200);
  });

  it('accepts a token bound to a nonstandard port (Express 5 host semantics)', async () => {
    const tokenWithPort: AccessToken = {
      ...VALID_TOKEN,
      resource: 'http://api.example.com:8443/api',
    };
    const app = makeApp(makeVerifier(tokenWithPort));
    const res = await request(app)
      .get('/resource')
      .set('Host', 'api.example.com:8443')
      .set('Authorization', 'Bearer valid-jwt');
    expect(res.status).toBe(200);
  });

  it('accepts a token bound to a nonstandard port when req.host strips it (Express 4 host semantics)', async () => {
    const tokenWithPort: AccessToken = {
      ...VALID_TOKEN,
      resource: 'http://api.example.com:8443/api',
    };
    const app = express();
    // Express 4's req.host is an alias for req.hostname: no port. Shadow the
    // Express 5 getter to simulate that; the Host header still carries the port.
    app.use((req, _res, next) => {
      Object.defineProperty(req, 'host', { value: 'api.example.com' });
      next();
    });
    app.use(requireBearerAuth({ verifier: makeVerifier(tokenWithPort) }));
    app.get('/resource', (_req, res) => res.json({ ok: true }));

    const res = await request(app)
      .get('/resource')
      .set('Host', 'api.example.com:8443')
      .set('Authorization', 'Bearer valid-jwt');
    expect(res.status).toBe(200);
  });

  it('returns 401 invalid_token when the signing key is not in the JWKS', async () => {
    const app = makeApp(makeThrowingVerifier(
      new JWKSKeyNotFoundError('Failed to find key "abc" of "https://zone.example.com"'),
    ));
    const res = await request(app)
      .get('/resource')
      .set('Authorization', 'Bearer forged-or-rotated-token');
    expect(res.status).toBe(401);
    expect(res.headers['www-authenticate']).toMatch(
      /^Bearer error="invalid_token", error_description="Unable to verify token signing key", resource_metadata="/,
    );
  });

  it('delegates genuinely unexpected verifier errors to the app error handler', async () => {
    const app = makeApp(makeThrowingVerifier(new Error('database on fire')));
    // Express's default error handler answers 500; the point is that the
    // middleware forwarded via next(error) rather than mapping the status.
    const res = await request(app)
      .get('/resource')
      .set('Authorization', 'Bearer valid-jwt');
    expect(res.status).toBe(500);
  });
});

describe('requireBearerAuth when the zone is unavailable (real TokenVerifier)', () => {
  // A real TokenVerifier over a JWKSOAuthKeyring and a stubbed fetch, so the
  // responses below come from the failures discovery and the JWKS fetch raise,
  // not from a verifier mock.
  const ISSUER = 'https://zone.example.com';
  const AUDIENCE = 'https://api.example.com';
  const DISCOVERY_URL = `${ISSUER}/.well-known/oauth-authorization-server`;
  const JWKS_URL = `${ISSUER}/.well-known/jwks.json`;
  const KID = 'test-key-1';
  const metadata = { issuer: ISSUER, jwks_uri: JWKS_URL, token_endpoint: `${ISSUER}/oauth/token` };
  const fetchSpy = jest.spyOn(globalThis, 'fetch');

  let privateKey: CryptoKey;
  let publicJwks: { keys: JsonWebKey[] };

  beforeAll(async () => {
    const pair = await crypto.subtle.generateKey(
      { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
      true,
      ['sign', 'verify'],
    );
    privateKey = pair.privateKey;
    const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
    publicJwks = { keys: [{ kty: jwk.kty, n: jwk.n, e: jwk.e, kid: KID, alg: 'RS256', use: 'sig' }] };
  });
  afterEach(() => fetchSpy.mockReset());
  afterAll(() => fetchSpy.mockRestore());

  function json(body: unknown, status = 200): Response {
    return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
  }

  function stubZone(handler: (url: string) => Response): void {
    fetchSpy.mockImplementation(async (input) => handler(String(input instanceof Request ? input.url : input)));
  }

  async function signToken(kid = KID, aud: string | string[] = AUDIENCE, issuer = ISSUER): Promise<string> {
    const keyring: PrivateKeyring = {
      key: async () => ({ key: privateKey, kid, issuer }),
    };
    const now = Math.floor(Date.now() / 1000);
    return new JWTSigner(keyring).sign({
      iss: issuer,
      sub: 'user-1',
      aud,
      client_id: 'svc-x',
      iat: now,
      exp: now + 3600,
    });
  }

  function realApp() {
    const verifier = new TokenVerifier({ issuer: ISSUER, audience: AUDIENCE, keyring: new JWKSOAuthKeyring() });
    return makeApp(verifier);
  }

  it.each<{ row: string; aud: string | string[]; status: number }>([
    { row: '8a: scalar match', aud: 'resource-b', status: 200 },
    { row: '8b: scalar mismatch', aud: 'resource-c', status: 401 },
    { row: '8c: array match', aud: ['resource-c', 'resource-b'], status: 200 },
    { row: '8d: array mismatch', aud: ['resource-c', 'resource-d'], status: 401 },
  ])('row $row', async ({ aud, status }) => {
    stubZone((url) => (url === DISCOVERY_URL ? json(metadata) : json(publicJwks)));
    const app = express();
    app.use(requireBearerAuth({ zoneUrl: ISSUER, audience: ['resource-a', 'resource-b'] }));
    app.get('/resource', (_req, res) => res.sendStatus(200));
    const res = await request(app).get('/resource').set('Authorization', `Bearer ${await signToken(KID, aud)}`);
    expect(res.status).toBe(status);
    if (status === 401) expect(res.headers['www-authenticate']).toMatch(/error="invalid_token"/);
  });

  it('row 8e: rejects an explicitly empty audience list at construction', () => {
    expect(() => requireBearerAuth({ zoneUrl: ISSUER, audience: [] })).toThrow(ConfigurationError);
  });

  it('row 7: legacy omission warns once and still accepts a valid token without checking its audience', async () => {
    stubZone(url => url === DISCOVERY_URL ? json(metadata) : json(publicJwks));
    const app = express();
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      app.use(requireBearerAuth({ zoneUrl: ISSUER }));
      app.use((_req, res) => { res.sendStatus(200); });
      await request(app).get('/').set('Authorization', `Bearer ${await signToken(KID, 'other-server')}`).expect(200);
      await request(app).get('/').expect(401).expect('WWW-Authenticate', /resource_metadata/);
      expect(warn).toHaveBeenCalledTimes(1);
      expect(warn).toHaveBeenCalledWith(expect.stringContaining('resource_identifier'));
    } finally {
      warn.mockRestore();
    }
  });

  it('rows 1, 8, 12, 12a, 12c, 15 and integration 2: binds the exact audience and challenge independently of host headers', async () => {
    stubZone(url => url === DISCOVERY_URL ? json(metadata) : json(publicJwks));
    const resourceIdentifier = 'https://api.example.com/mcp?k=v';
    const app = express();
    app.enable('trust proxy');
    app.use(requireBearerAuth({ zoneUrl: ISSUER, resourceIdentifier }));
    app.use((_req, res) => { res.sendStatus(200); });
    const incoming = (path: string) => request(app).get(path)
      .set('Host', 'internal.example').set('X-Forwarded-Host', 'attacker.example').set('X-Forwarded-Proto', 'http');
    const challenge = 'Bearer resource_metadata="https://api.example.com/.well-known/oauth-protected-resource/mcp?k=v"';
    await request(app).get('/mcp?k=v').set('Host', 'internal.example').expect(401).expect('WWW-Authenticate', challenge);
    await incoming('/mcp?k=v').expect(401).expect('WWW-Authenticate', challenge);
    await incoming('/mcp?k=other').expect(401).expect('WWW-Authenticate', 'Bearer');
    await incoming('/tools').expect(401).expect('WWW-Authenticate', 'Bearer');
    await incoming('/mcp?k=v').set('Authorization', `Bearer ${await signToken(KID, resourceIdentifier)}`).expect(200);
    await incoming('/mcp?k=v').set('Authorization', `Bearer ${await signToken(KID, 'https://api.example.com/other')}`)
      .expect(401).expect('WWW-Authenticate', /invalid_token/);
  });

  it('row 12b and route gate 2a: treats the bare URL as root only for the challenge', async () => {
    const app = express();
    app.use(requireBearerAuth({ zoneUrl: ISSUER, resourceIdentifier: AUDIENCE }));
    const challenge = /resource_metadata="https:\/\/api\.example\.com\/\.well-known\/oauth-protected-resource"/;
    await request(app).get('/').expect(401).expect('WWW-Authenticate', challenge);
    await request(app).get('/').set('Authorization', `Bearer ${await signToken(KID, AUDIENCE + '/')}`)
      .expect(401).expect('WWW-Authenticate', challenge);
  });

  it('rows 12d and route gate 2: uses the full target for a mounted handler and exposes host-root metadata (metadata row 10)', async () => {
    const app = express();
    const config = createKeycardMiddleware({ zoneUrl: ISSUER, resourceIdentifier: AUDIENCE + '/app/mcp' });
    app.use(config.metadataRouter());
    app.use('/app', config.requireBearerAuth());
    await request(app).get('/app/mcp').expect(401)
      .expect('WWW-Authenticate', 'Bearer resource_metadata="https://api.example.com/.well-known/oauth-protected-resource/app/mcp"');
    await request(app).get('/.well-known/oauth-protected-resource/app/mcp').expect(200)
      .expect({ resource: AUDIENCE + '/app/mcp', authorization_servers: [ISSUER] });
  });

  it.each([
    { row: '8a, 8f', aud: 'resource-b', status: 200 },
    { row: '8b, 8f', aud: 'resource-c', status: 401 },
    { row: '8c', aud: ['resource-c', 'resource-b'], status: 200 },
    { row: '8d', aud: ['resource-c', 'resource-d'], status: 401 },
  ])('rows $row: explicit list accepts any configured value without discovery', async ({ aud, status }) => {
    stubZone(url => url === DISCOVERY_URL ? json(metadata) : json(publicJwks));
    const app = express();
    app.use(requireBearerAuth({ zoneUrl: ISSUER, multiResource: true, audience: ['resource-a', 'resource-b'] }));
    app.use((_req, res) => { res.sendStatus(200); });
    const res = await request(app).get('/').set('Authorization', `Bearer ${await signToken(KID, aud)}`).expect(status);
    if (status === 401) {
      expect(res.headers['www-authenticate']).toMatch(/invalid_token/);
      expect(res.headers['www-authenticate']).not.toContain('resource_metadata');
    }
  });

  it('rows 8g, 8h and route gate 7: verifies URN and unrestricted modes without discovery', async () => {
    stubZone(url => url === DISCOVERY_URL ? json(metadata) : json(publicJwks));
    const urn = 'urn:example:service';
    for (const mode of [{ resourceIdentifier: urn }, { allowAnyAudience: true }]) {
      const app = express();
      const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
      try {
        app.use(requireBearerAuth({ zoneUrl: ISSUER, ...mode }));
        expect(warn).not.toHaveBeenCalled();
      } finally {
        warn.mockRestore();
      }
      app.use((_req, res) => { res.sendStatus(200); });
      await request(app).get('/').expect(401).expect('WWW-Authenticate', 'Bearer');
      await request(app).get('/').set('Authorization', `Bearer ${await signToken(KID, urn)}`).expect(200);
      const wrong = await signToken(KID, 'urn:example:other');
      await request(app).get('/').set('Authorization', `Bearer ${wrong}`).expect(mode.allowAnyAudience ? 200 : 401);
      const [header, payload, signature] = wrong.split('.');
      const broken = `${header}.${payload}.${signature[0] === 'A' ? 'B' : 'A'}${signature.slice(1)}`;
      const result = await request(app).get('/').set('Authorization', `Bearer ${broken}`).expect(401);
      expect(result.headers['www-authenticate']).not.toContain('resource_metadata');
    }
  });

  it('rows 16, 16a and 16c: selects request zones before reading a bearer token', async () => {
    stubZone(url => url.endsWith('/oauth-authorization-server')
      ? json({ ...metadata, issuer: 'https://zabc123.keycard.cloud', jwks_uri: 'https://zabc123.keycard.cloud/jwks' })
      : json(publicJwks));
    const resourceIdentifiersByZone = { zabc123: AUDIENCE + '/zabc123/mcp', b: AUDIENCE + '/b/mcp' };
    const app = express();
    app.use(requireBearerAuth({
      zoneUrl: 'https://keycard.cloud', resourceIdentifiersByZone, zoneResolver: req => req.path.split('/')[1],
    }));
    app.use((_req, res) => { res.sendStatus(200); });
    const discovery = /oauth-protected-resource\/zabc123\/mcp/;
    await request(app).get('/zabc123/mcp').expect(401).expect('WWW-Authenticate', discovery);
    await request(app).get('/').expect(401).expect('WWW-Authenticate', 'Bearer');
    await request(app).get('/c/mcp').expect(401).expect('WWW-Authenticate', 'Bearer');
    for (const [aud, status] of [[resourceIdentifiersByZone.zabc123, 200], [resourceIdentifiersByZone.b, 401]] as const) {
      const result = await request(app).get('/zabc123/mcp').set('Authorization', `Bearer ${await signToken(KID, aud, 'https://zabc123.keycard.cloud')}`).expect(status);
      if (status === 401) expect(result.headers['www-authenticate']).toMatch(discovery);
    }
  });

  it('rejects a pre-built verifier whose issuer cannot be bound to the resolved zone', () => {
    const resourceIdentifier = AUDIENCE + '/b/mcp';
    const verifier = new TokenVerifier({ issuer: 'https://a.keycard.cloud', audience: resourceIdentifier });
    expect(() => requireBearerAuth({
      verifier, resourceIdentifiersByZone: { b: resourceIdentifier }, zoneResolver: () => 'b',
    })).toThrow(ConfigurationError);
  });

  it.each([
    { allowAnyAudience: true },
    { multiResource: true, audience: [AUDIENCE], resourceIdentifiersByZone: { a: AUDIENCE } },
  ])('returns a valid bearer challenge when the verifier error contains invalid header characters: %j', async mode => {
    const verify = jest.spyOn(JWTVerifier.prototype, 'verify')
      .mockRejectedValue(new InvalidTokenError('Unsupported JWT algorithm: "\u0100"'));
    try {
      const app = express();
      app.use(requireBearerAuth({ zoneUrl: 'https://keycard.cloud', ...mode }));
      const result = await request(app).get('/').set('Authorization', 'Bearer token').expect(401);
      expect(result.headers['www-authenticate']).toContain('error="invalid_token", error_description="Unsupported JWT algorithm:    "');
    } finally {
      verify.mockRestore();
    }
  });

  it('omits the bearer token when printing auth from the inline verifier', async () => {
    stubZone(url => url === DISCOVERY_URL ? json(metadata) : json(publicJwks));
    const token = await signToken();
    const app = express();
    app.use(requireBearerAuth({ zoneUrl: ISSUER, allowAnyAudience: true }));
    app.get('/', (req, res) => {
      const auth = (req as AuthenticatedRequest).auth;
      expect(auth.token).toBe(token);
      res.send(inspect(auth));
    });
    const response = await request(app).get('/').set('Authorization', `Bearer ${token}`).expect(200);
    expect(response.text).toContain('AccessToken');
    expect(response.text).not.toContain(token);
  });

  it('row 17: uses the configured issuers for a shared discovery URL', async () => {
    stubZone(url => url.endsWith('/oauth-authorization-server')
      ? json({ ...metadata, issuer: new URL(url).origin, jwks_uri: new URL('/jwks', url).href })
      : json(publicJwks));
    const identifier = AUDIENCE + '/mcp';
    const app = express();
    app.use(requireBearerAuth({
      zoneUrl: 'https://keycard.cloud', multiResource: true, audience: [identifier],
      resourceIdentifiersByZone: { a: identifier, b: identifier },
    }));
    app.use((_req, res) => { res.sendStatus(200); });
    await request(app).get('/mcp').expect(401).expect('WWW-Authenticate', /oauth-protected-resource\/mcp/);
    for (const [zone, status] of [['a', 200], ['b', 200], ['c', 401]] as const) {
      await request(app).get('/mcp').set('Authorization', `Bearer ${await signToken(KID, identifier, `https://${zone}.keycard.cloud`)}`).expect(status);
    }
    expect(fetchSpy.mock.calls.map(([url]) => String(url)).some(url => url.includes('c.keycard.cloud'))).toBe(false);
  });

  it('rows 8e, 13, 14b, 16b, 16d and 17a: rejects invalid binding combinations at construction', () => {
    const resourceIdentifiersByZone = { a: AUDIENCE };
    for (const options of [
      { multiResource: true, audience: [] },
      { multiResource: true, audience: AUDIENCE },
      { multiResource: true, audience: { a: AUDIENCE } },
      { resourceIdentifier: AUDIENCE, allowAnyAudience: true },
      { resourceIdentifier: AUDIENCE, resourceIdentifiersByZone },
      { resourceIdentifiersByZone, allowAnyAudience: true },
      { resourceIdentifiersByZone },
      { multiResource: true, audience: [AUDIENCE], resourceIdentifiersByZone: { a: AUDIENCE, b: AUDIENCE + '/other' } },
    ]) expect(() => requireBearerAuth({ zoneUrl: ISSUER, ...options })).toThrow(ConfigurationError);
  });

  it('rejects an HTTP(S) resourceIdentifier with enableMultiZone, so the base URL is never advertised', () => {
    const options = { zoneUrl: ISSUER, enableMultiZone: true, resourceIdentifier: AUDIENCE };
    expect(() => requireBearerAuth(options)).toThrow(ConfigurationError);
    expect(() => createKeycardMiddleware(options)).toThrow(ConfigurationError);
  });

  it('accepts verifier-only bindings with enableMultiZone', () => {
    for (const options of [
      { resourceIdentifier: 'urn:example:api' },
      { multiResource: true, audience: [AUDIENCE] },
      { allowAnyAudience: true },
    ]) {
      expect(() => requireBearerAuth({ zoneUrl: ISSUER, enableMultiZone: true, zoneResolver: subdomainZoneResolver, ...options }))
        .not.toThrow();
    }
  });

  it.each(['api.example.com', 'https:///mcp', 'https://user@api.example.com/mcp', 'https://api.example.com/mcp#fragment', 'urn:'])(
    'rejects invalid identifiers at construction: %s',
    resourceIdentifier => {
      expect(() => requireBearerAuth({ zoneUrl: ISSUER, resourceIdentifier })).toThrow(ConfigurationError);
    },
  );

  it('route gate row 6: omits discovery on a different protected route with insufficient scope', async () => {
    stubZone(url => url === DISCOVERY_URL ? json(metadata) : json(publicJwks));
    const identifier = AUDIENCE + '/mcp';
    const app = express();
    app.use(requireBearerAuth({ zoneUrl: ISSUER, resourceIdentifier: identifier, requiredScopes: ['write'] }));
    const result = await request(app).get('/tools').set('Authorization', `Bearer ${await signToken(KID, identifier)}`).expect(403);
    expect(result.headers['www-authenticate']).toMatch(/insufficient_scope/);
    expect(result.headers['www-authenticate']).not.toContain('resource_metadata');
  });

  it('answers 503 temporarily_unavailable with no challenge when the JWKS fetch fails', async () => {
    stubZone((url) => (url === DISCOVERY_URL ? json(metadata) : json({ error: 'down' }, 503)));
    const res = await request(realApp())
      .get('/resource')
      .set('Authorization', `Bearer ${await signToken()}`);
    expect(res.status).toBe(503);
    expect(res.body).toEqual({ error: 'temporarily_unavailable' });
    expect(res.headers['www-authenticate']).toBeUndefined();
  });

  it('answers 503 temporarily_unavailable with no challenge when discovery fails', async () => {
    stubZone(() => json({ error: 'down' }, 500));
    const res = await request(realApp())
      .get('/resource')
      .set('Authorization', `Bearer ${await signToken()}`);
    expect(res.status).toBe(503);
    expect(res.body).toEqual({ error: 'temporarily_unavailable' });
    expect(res.headers['www-authenticate']).toBeUndefined();
  });

  it('answers 401 invalid_token for a kid absent from a JWKS that loaded', async () => {
    stubZone((url) => (url === DISCOVERY_URL ? json(metadata) : json(publicJwks)));
    const res = await request(realApp())
      .get('/resource')
      .set('Authorization', `Bearer ${await signToken('kid-rotated')}`);
    expect(res.status).toBe(401);
    expect(res.headers['www-authenticate']).toMatch(/^Bearer error="invalid_token"/);
  });

  it('answers 200 for a token signed by a key the JWKS carries', async () => {
    stubZone((url) => (url === DISCOVERY_URL ? json(metadata) : json(publicJwks)));
    const res = await request(realApp())
      .get('/resource')
      .set('Authorization', `Bearer ${await signToken()}`);
    expect(res.status).toBe(200);
    expect(res.body.clientId).toBe('svc-x');
  });
});

describe('requireBearerAuth zoneResolver', () => {
  function makeZoneVerifier(result: AccessToken | null) {
    return {
      verifyToken: jest.fn<() => Promise<AccessToken | null>>().mockResolvedValue(result),
      verifyTokenForZone: jest.fn<() => Promise<AccessToken | null>>().mockResolvedValue(result),
      clearCache: jest.fn(),
    } as unknown as TokenVerifier;
  }

  it('verifies via verifyTokenForZone with the resolved zone ID', async () => {
    const verifier = makeZoneVerifier(VALID_TOKEN);
    const app = express();
    app.use(requireBearerAuth({ verifier, zoneResolver: () => 'zone-a' }));
    app.get('/resource', (_req, res) => res.json({ ok: true }));

    const res = await request(app)
      .get('/resource')
      .set('Authorization', 'Bearer valid-jwt');
    expect(res.status).toBe(200);
    expect(verifier.verifyTokenForZone).toHaveBeenCalledWith('valid-jwt', 'zone-a');
    expect(verifier.verifyToken).not.toHaveBeenCalled();
  });

  it('falls back to verifyToken when the resolver returns undefined', async () => {
    const verifier = makeZoneVerifier(VALID_TOKEN);
    const app = express();
    app.use(requireBearerAuth({ verifier, zoneResolver: () => undefined }));
    app.get('/resource', (_req, res) => res.json({ ok: true }));

    const res = await request(app)
      .get('/resource')
      .set('Authorization', 'Bearer valid-jwt');
    expect(res.status).toBe(200);
    expect(verifier.verifyToken).toHaveBeenCalledWith('valid-jwt');
    expect(verifier.verifyTokenForZone).not.toHaveBeenCalled();
  });

  it('uses verifyToken when no resolver is configured', async () => {
    const verifier = makeZoneVerifier(VALID_TOKEN);
    const app = makeApp(verifier);
    const res = await request(app)
      .get('/resource')
      .set('Authorization', 'Bearer valid-jwt');
    expect(res.status).toBe(200);
    expect(verifier.verifyToken).toHaveBeenCalledWith('valid-jwt');
    expect(verifier.verifyTokenForZone).not.toHaveBeenCalled();
  });
});

describe('subdomainZoneResolver', () => {
  function reqWithHost(host: string) {
    return { host } as unknown as express.Request;
  }

  it('extracts the leftmost label of a subdomain host', () => {
    expect(subdomainZoneResolver(reqWithHost('zone-a.api.example.com'))).toBe('zone-a');
    expect(subdomainZoneResolver(reqWithHost('zone-b.keycard.cloud'))).toBe('zone-b');
  });

  it('returns undefined when the leftmost label is not a DNS label', () => {
    for (const label of ['zone/a', 'zone@a', 'zone%2fa', 'zone a', 'a'.repeat(64), '-zone', 'zone-']) {
      expect(subdomainZoneResolver(reqWithHost(`${label}.api.example.com`))).toBeUndefined();
    }
    expect(subdomainZoneResolver(reqWithHost('.api.example.com'))).toBeUndefined();
  });

  it('strips a port before extracting the zone', () => {
    expect(subdomainZoneResolver(reqWithHost('zone-a.api.example.com:8443'))).toBe('zone-a');
  });

  it('returns undefined when the host has fewer than three labels', () => {
    expect(subdomainZoneResolver(reqWithHost('example.com'))).toBeUndefined();
    expect(subdomainZoneResolver(reqWithHost('localhost'))).toBeUndefined();
    expect(subdomainZoneResolver(reqWithHost('localhost:3000'))).toBeUndefined();
  });

  it('returns undefined for IP literals', () => {
    expect(subdomainZoneResolver(reqWithHost('127.0.0.1'))).toBeUndefined();
    expect(subdomainZoneResolver(reqWithHost('10.0.0.1:8080'))).toBeUndefined();
    expect(subdomainZoneResolver(reqWithHost('[::1]'))).toBeUndefined();
  });

  it('returns undefined when the host is empty', () => {
    expect(subdomainZoneResolver(reqWithHost(''))).toBeUndefined();
  });
});
