import { jest } from '@jest/globals';
import express from 'express';
import request from 'supertest';
import { grant } from './grant.js';
import type { AccessToken } from '@keycardai/oauth/server';

const ZONE_URL = 'https://zone.keycard.cloud';
const RESOURCE = 'https://api.example.com';

const VALID_AUTH: AccessToken = {
  token: 'bearer-tok',
  clientId: 'svc-x',
  scopes: ['read'],
};

type FetchInput = Parameters<typeof fetch>[0];

function makeApp(resources: string[], auth?: AccessToken | null) {
  const app = express();

  // Simulate requireBearerAuth by directly setting req.auth
  app.use((req, _res, next) => {
    if (auth !== null && auth !== undefined) {
      (req as any).auth = auth;
    }
    next();
  });

  app.use(grant(resources, { zoneUrl: ZONE_URL }));

  app.get('/data', (req, res) => {
    const ctx = (req as any).accessContext;
    res.json({ status: ctx.getStatus() });
  });

  return app;
}

describe('grant', () => {
  let originalFetch: typeof fetch;
  let fetchMock: jest.Mock;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
    fetchMock = jest.fn(async (input: FetchInput) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.includes('/.well-known/')) {
        return new Response(
          JSON.stringify({ issuer: ZONE_URL, token_endpoint: `${ZONE_URL}/token` }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      return new Response(
        JSON.stringify({ access_token: 'resource-tok', token_type: 'bearer' }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('sets req.accessContext with a successful token exchange', async () => {
    const app = makeApp([RESOURCE], VALID_AUTH);
    const res = await request(app).get('/data');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('success');
  });

  it('responds 401 with a Bearer challenge and skips the handler when req.auth is absent', async () => {
    const handler = jest.fn();
    const app = express();
    app.use(grant([RESOURCE], { zoneUrl: ZONE_URL }));
    app.get('/data', (_req, res) => {
      handler();
      res.json({ ok: true });
    });

    const res = await request(app).get('/data');
    expect(res.status).toBe(401);
    expect(res.headers['www-authenticate']).toMatch(/^Bearer resource_metadata="/);
    expect(res.body.error).toBe('invalid_request');
    expect(handler).not.toHaveBeenCalled();
  });

  it('merges tokens from stacked grant middlewares into one accessContext', async () => {
    const RESOURCE_B = 'https://api-b.example.com';
    const app = express();
    app.use((req, _res, next) => { (req as any).auth = VALID_AUTH; next(); });
    app.use(grant([RESOURCE], { zoneUrl: ZONE_URL }));
    app.use(grant([RESOURCE_B], { zoneUrl: ZONE_URL }));
    app.get('/data', (req, res) => {
      const ctx = (req as any).accessContext;
      res.json({
        a: ctx.access(RESOURCE).accessToken,
        b: ctx.access(RESOURCE_B).accessToken,
        status: ctx.getStatus(),
      });
    });

    const res = await request(app).get('/data');
    expect(res.status).toBe(200);
    expect(res.body.a).toBe('resource-tok');
    expect(res.body.b).toBe('resource-tok');
    expect(res.body.status).toBe('success');
  });

  it('uses the substitute-user impersonation exchange when userIdentifier is set', async () => {
    const app = express();
    app.use((req, _res, next) => { (req as any).auth = VALID_AUTH; next(); });
    app.use(grant([RESOURCE], {
      zoneUrl: ZONE_URL,
      userIdentifier: () => 'alice@example.com',
    }));
    app.get('/data', (req, res) => {
      const ctx = (req as any).accessContext;
      res.json({ status: ctx.getStatus() });
    });

    const res = await request(app).get('/data');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('success');

    const tokenCall = fetchMock.mock.calls.find(([url]) =>
      typeof url === 'string' && url.endsWith('/token'),
    );
    expect(tokenCall).toBeDefined();
    const body = ((tokenCall![1] as RequestInit).body ?? '') as string;
    const params = new URLSearchParams(body);
    expect(params.get('subject_token_type')).toBe(
      'urn:keycard:params:oauth:token-type:substitute-user',
    );
    const subjectToken = params.get('subject_token')!;
    const payloadSegment = subjectToken.split('.')[1];
    const payload = JSON.parse(
      Buffer.from(payloadSegment, 'base64url').toString('utf8'),
    );
    expect(payload.sub).toBe('alice@example.com');
  });

  it('records a global error when the userIdentifier resolver throws', async () => {
    const app = express();
    app.use((req, _res, next) => { (req as any).auth = VALID_AUTH; next(); });
    app.use(grant([RESOURCE], {
      zoneUrl: ZONE_URL,
      userIdentifier: () => { throw new Error('resolver exploded'); },
    }));
    app.get('/data', (req, res) => {
      const ctx = (req as any).accessContext;
      res.json({ status: ctx.getStatus(), error: ctx.getError() });
    });

    const res = await request(app).get('/data');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('error');
    expect(res.body.error.message).toContain('userIdentifier');
    // No exchange attempted
    const tokenCall = fetchMock.mock.calls.find(([url]) =>
      typeof url === 'string' && url.endsWith('/token'),
    );
    expect(tokenCall).toBeUndefined();
  });

  it('sets a resource error when the token endpoint returns an OAuth error', async () => {
    fetchMock.mockImplementation(async (input: FetchInput) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.includes('/.well-known/')) {
        return new Response(
          JSON.stringify({ issuer: ZONE_URL, token_endpoint: `${ZONE_URL}/token` }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      return new Response(
        JSON.stringify({ error: 'invalid_grant', error_description: 'token expired' }),
        { status: 400, headers: { 'content-type': 'application/json' } },
      );
    });

    const app = makeApp([RESOURCE], VALID_AUTH);
    const res = await request(app).get('/data');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('partial_error');
  });

  it('throws at construction when neither zoneUrl nor zoneId is provided', () => {
    expect(() => grant([RESOURCE], {} as any)).toThrow(/zoneUrl.*zoneId/);
  });

  it('resolves zoneId dynamically from a function and routes the exchange', async () => {
    const resolvedZone = 'zone-abc';
    const dynamicZoneUrl = `https://${resolvedZone}.keycard.cloud`;
    // Use an auth token whose clientId matches the zone we want to resolve
    const zoneAuth: AccessToken = { ...VALID_AUTH, clientId: resolvedZone };

    fetchMock.mockImplementation(async (input: FetchInput) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.includes('/.well-known/')) {
        return new Response(
          JSON.stringify({ issuer: dynamicZoneUrl, token_endpoint: `${dynamicZoneUrl}/token` }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      return new Response(
        JSON.stringify({ access_token: 'zone-tok', token_type: 'bearer' }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    });

    const app = express();
    app.use((req, _res, next) => {
      (req as any).auth = zoneAuth;
      next();
    });
    app.use(grant([RESOURCE], {
      // Extract zone from auth.clientId at request time
      zoneId: (auth) => auth.clientId,
    }));
    app.get('/data', (req, res) => {
      const ctx = (req as any).accessContext;
      res.json({ status: ctx.getStatus() });
    });

    const res = await request(app).get('/data');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('success');

    // Confirm the exchange hit the zone-specific token endpoint
    const tokenCall = fetchMock.mock.calls.find(([url]) =>
      typeof url === 'string' && url.includes(resolvedZone) && !url.includes('.well-known'),
    );
    expect(tokenCall).toBeDefined();
  });

  it('routes issuer-keyed multi-zone ClientSecret credentials by the resolved zone issuer', async () => {
    const { ClientSecret } = await import('@keycardai/oauth/server');
    const credential = new ClientSecret({
      'https://zone-a.keycard.cloud': ['id-a', 'sec-a'],
      'https://zone-b.keycard.cloud': ['id-b', 'sec-b'],
    });

    // Return zone-specific metadata so the token endpoint URL reflects the zone
    fetchMock.mockImplementation(async (input: FetchInput) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.includes('/.well-known/')) {
        const zone = url.includes('zone-b') ? 'zone-b' : 'zone-a';
        const base = `https://${zone}.keycard.cloud`;
        return new Response(
          JSON.stringify({ issuer: base, token_endpoint: `${base}/token` }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      return new Response(
        JSON.stringify({ access_token: 'tok', token_type: 'bearer' }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    });

    const app = express();
    app.use((req, _res, next) => {
      (req as any).auth = { ...VALID_AUTH, clientId: 'zone-b' };
      next();
    });
    app.use(grant([RESOURCE], {
      zoneId: (auth) => auth.clientId,
      applicationCredential: credential,
    }));
    app.get('/data', (req, res) => {
      const ctx = (req as any).accessContext;
      res.json({ status: ctx.getStatus() });
    });

    const res = await request(app).get('/data');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('success');

    // The token endpoint call should use Basic auth for zone-b credentials
    const tokenCall = fetchMock.mock.calls.find(([url]) =>
      typeof url === 'string' && url.includes('zone-b') && !url.includes('.well-known'),
    );
    expect(tokenCall).toBeDefined();
    const authHeader = ((tokenCall![1] as RequestInit).headers as Record<string, string>)['Authorization'];
    expect(authHeader).toBe(`Basic ${btoa('id-b:sec-b')}`);
  });

  it('calls next(err) when the zoneId resolver function throws', async () => {
    const boom = new Error('zone resolver exploded');
    const app = express();
    app.use((req, _res, next) => { (req as any).auth = VALID_AUTH; next(); });
    app.use(grant([RESOURCE], { zoneId: () => { throw boom; } }));
    // Express error handler
    app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
      res.status(500).json({ error: err.message });
    });

    const res = await request(app).get('/anything');
    expect(res.status).toBe(500);
    expect(res.body.error).toBe('zone resolver exploded');
  });

  it('records a resource error when zoneId resolves to a zone with no matching credential', async () => {
    const { ClientSecret } = await import('@keycardai/oauth/server');
    // Dict has zone-a's issuer only; the request auth says zone-x (no entry)
    const credential = new ClientSecret({ 'https://zone-a.keycard.cloud': ['id-a', 'sec-a'] });

    fetchMock.mockImplementation(async (input: FetchInput) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.includes('/.well-known/')) {
        return new Response(
          JSON.stringify({ issuer: 'https://zone-x.keycard.cloud', token_endpoint: 'https://zone-x.keycard.cloud/token' }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      // AS responds 401 — no valid credentials were sent
      return new Response(
        JSON.stringify({ error: 'invalid_client' }),
        { status: 401, headers: { 'content-type': 'application/json' } },
      );
    });

    const app = express();
    app.use((req, _res, next) => {
      (req as any).auth = { ...VALID_AUTH, clientId: 'zone-x' };
      next();
    });
    app.use(grant([RESOURCE], {
      zoneId: (auth) => auth.clientId,
      applicationCredential: credential,
    }));
    app.get('/data', (req, res) => {
      const ctx = (req as any).accessContext;
      res.json({ status: ctx.getStatus() });
    });

    const res = await request(app).get('/data');
    expect(res.status).toBe(200);
    // Exchange fails because the credential has no entry for zone-x
    expect(res.body.status).toBe('partial_error');
  });
});
