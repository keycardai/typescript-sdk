import { jest } from '@jest/globals';
import express from 'express';
import request from 'supertest';
import { requireBearerAuth } from './bearerAuth.js';
import { TokenVerifier } from '@keycardai/oauth/server';
import type { AccessToken } from '@keycardai/oauth/server';

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
});
