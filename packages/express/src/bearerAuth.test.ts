import { jest } from '@jest/globals';
import express from 'express';
import request from 'supertest';
import { requireBearerAuth, subdomainZoneResolver } from './bearerAuth.js';
import { TokenVerifier } from '@keycardai/oauth/server';
import type { AccessToken } from '@keycardai/oauth/server';
import {
  JWKSKeyNotFoundError,
  JWKSFetchError,
  JWKSDiscoveryError,
} from '@keycardai/oauth/errors';

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

  it('accepts a token with no resource claim (audience not enforced by token)', async () => {
    const tokenNoResource: AccessToken = { ...VALID_TOKEN, resource: undefined };
    const app = makeApp(makeVerifier(tokenNoResource));
    const res = await request(app)
      .get('/resource')
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

  it.each([
    ['JWKSFetchError', new JWKSFetchError('JWKS endpoint returned 503')],
    ['JWKSDiscoveryError', new JWKSDiscoveryError('Failed to discover authorization server metadata')],
  ])('returns 503 (not 500) when the verifier throws %s', async (_name, error) => {
    const app = makeApp(makeThrowingVerifier(error));
    const res = await request(app)
      .get('/resource')
      .set('Authorization', 'Bearer valid-looking-token');
    expect(res.status).toBe(503);
    expect(res.body).toEqual({ error: 'temporarily_unavailable' });
    expect(res.headers['www-authenticate']).toBeUndefined();
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
