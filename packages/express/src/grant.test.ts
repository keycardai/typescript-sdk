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

  it('sets a global error on accessContext when req.auth is absent', async () => {
    const app = makeApp([RESOURCE], null);
    const res = await request(app).get('/data');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('error');
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
});
