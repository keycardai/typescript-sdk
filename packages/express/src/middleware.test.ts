import { jest } from '@jest/globals';
import express from 'express';
import request from 'supertest';
import { createKeycardMiddleware } from './middleware.js';
import type { AccessToken } from '@keycardai/oauth/server';

const BASE_ZONE_URL = 'https://keycard.cloud';
const ZONE_URL = 'https://zone.keycard.cloud';
const RESOURCE = 'https://api.example.com';

const VALID_AUTH: AccessToken = {
  token: 'bearer-tok',
  clientId: 'svc-x',
  scopes: ['read'],
};

type FetchInput = Parameters<typeof fetch>[0];

function b64url(value: object): string {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

/**
 * Builds a structurally valid RS256 JWT (bogus signature). Verification
 * fails at the JWKS key lookup, after issuer/audience policy checks, which
 * is exactly the boundary these wiring tests observe.
 */
function makeJwt(payload: Record<string, unknown>): string {
  const header = { alg: 'RS256', kid: 'k1' };
  return `${b64url(header)}.${b64url(payload)}.${Buffer.from('sig').toString('base64url')}`;
}

function makeClaims(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const now = Math.floor(Date.now() / 1000);
  return {
    iss: 'https://zone-a.keycard.cloud',
    aud: 'my-api',
    sub: 'user-1',
    client_id: 'client-1',
    exp: now + 3600,
    iat: now,
    scope: 'read',
    ...overrides,
  };
}

describe('createKeycardMiddleware', () => {
  let originalFetch: typeof fetch;
  let fetchMock: jest.Mock;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
    fetchMock = jest.fn(async (input: FetchInput) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.includes('/.well-known/')) {
        const origin = new URL(url).origin;
        return new Response(
          JSON.stringify({
            issuer: origin,
            token_endpoint: `${origin}/token`,
            jwks_uri: `${origin}/jwks.json`,
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      if (url.includes('/jwks.json')) {
        return new Response(
          JSON.stringify({ keys: [] }),
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

  it('throws at construction when neither zoneUrl nor zoneId is provided', () => {
    expect(() => createKeycardMiddleware({})).toThrow(/zoneUrl.*zoneId/);
  });

  describe('requireBearerAuth passthrough', () => {
    it('passes zoneResolver and enableMultiZone through to zone-scoped verification', async () => {
      const zoneResolver = jest.fn(() => 'zone-a');
      const keycard = createKeycardMiddleware({
        zoneUrl: BASE_ZONE_URL,
        enableMultiZone: true,
        audience: 'my-api',
        zoneResolver,
      });

      const app = express();
      app.use(keycard.requireBearerAuth());
      app.get('/data', (_req, res) => res.json({ ok: true }));

      // Signature is bogus, so the request fails; the wiring is observable
      // through the resolver call and the zone-scoped JWKS discovery fetch.
      const res = await request(app)
        .get('/data')
        .set('Authorization', `Bearer ${makeJwt(makeClaims())}`);
      expect(res.status).toBe(401);
      expect(zoneResolver).toHaveBeenCalledTimes(1);
      const discoveryCall = fetchMock.mock.calls.find(([input]) => {
        const url = String(input);
        return url.startsWith('https://zone-a.keycard.cloud/') && url.includes('/.well-known/');
      });
      expect(discoveryCall).toBeDefined();
    });

    it('passes audience through: a token with the wrong aud is rejected before any key lookup', async () => {
      const keycard = createKeycardMiddleware({
        zoneUrl: BASE_ZONE_URL,
        enableMultiZone: true,
        audience: 'my-api',
        zoneResolver: () => 'zone-a',
      });

      const app = express();
      app.use(keycard.requireBearerAuth());
      app.get('/data', (_req, res) => res.json({ ok: true }));

      const res = await request(app)
        .get('/data')
        .set('Authorization', `Bearer ${makeJwt(makeClaims({ aud: 'other-api' }))}`);
      expect(res.status).toBe(401);
      // Audience policy fails closed before the keyring runs, so no fetch.
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it('still passes requiredScopes per call', async () => {
      const keycard = createKeycardMiddleware({ zoneUrl: ZONE_URL });
      const app = express();
      app.use(keycard.requireBearerAuth({ requiredScopes: ['admin'] }));
      app.get('/data', (_req, res) => res.json({ ok: true }));

      // No valid signing key is reachable, so use a missing header to hit
      // the cheap 401 path and confirm the middleware is wired at all.
      const res = await request(app).get('/data');
      expect(res.status).toBe(401);
    });
  });

  describe('grant passthrough', () => {
    function makeGrantApp(keycard: ReturnType<typeof createKeycardMiddleware>, grantOptions?: Parameters<ReturnType<typeof createKeycardMiddleware>['grant']>[1]) {
      const app = express();
      app.use((req, _res, next) => {
        (req as express.Request & { auth: AccessToken }).auth = VALID_AUTH;
        next();
      });
      app.use(keycard.grant([RESOURCE], grantOptions));
      app.get('/data', (req, res) => {
        const ctx = (req as express.Request & { accessContext: { getStatus(): string } }).accessContext;
        res.json({ status: ctx.getStatus() });
      });
      return app;
    }

    function tokenCalls() {
      return fetchMock.mock.calls.filter(
        ([url]) => typeof url === 'string' && url.endsWith('/token'),
      );
    }

    it('passes a factory-level userIdentifier through to the impersonation exchange', async () => {
      const keycard = createKeycardMiddleware({
        zoneUrl: ZONE_URL,
        userIdentifier: () => 'alice@example.com',
      });

      const res = await request(makeGrantApp(keycard)).get('/data');
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('success');

      const [tokenCall] = tokenCalls();
      expect(tokenCall).toBeDefined();
      const params = new URLSearchParams(((tokenCall[1] as RequestInit).body ?? '') as string);
      expect(params.get('subject_token_type')).toBe(
        'urn:keycard:params:oauth:token-type:substitute-user',
      );
      const payloadSegment = params.get('subject_token')!.split('.')[1];
      const payload = JSON.parse(Buffer.from(payloadSegment, 'base64url').toString('utf8'));
      expect(payload.sub).toBe('alice@example.com');
    });

    it('passes factory-level requestScopes through to the exchange', async () => {
      const keycard = createKeycardMiddleware({
        zoneUrl: ZONE_URL,
        requestScopes: 'read write',
      });

      const res = await request(makeGrantApp(keycard)).get('/data');
      expect(res.status).toBe(200);

      const [tokenCall] = tokenCalls();
      const params = new URLSearchParams(((tokenCall[1] as RequestInit).body ?? '') as string);
      expect(params.get('scope')).toBe('read write');
    });

    it('lets per-call options override the factory-level defaults', async () => {
      const keycard = createKeycardMiddleware({
        zoneUrl: ZONE_URL,
        requestScopes: 'read',
        userIdentifier: () => 'alice@example.com',
      });

      const res = await request(
        makeGrantApp(keycard, {
          requestScopes: 'admin',
          userIdentifier: () => 'bob@example.com',
        }),
      ).get('/data');
      expect(res.status).toBe(200);

      const [tokenCall] = tokenCalls();
      const params = new URLSearchParams(((tokenCall[1] as RequestInit).body ?? '') as string);
      expect(params.get('scope')).toBe('admin');
      const payloadSegment = params.get('subject_token')!.split('.')[1];
      const payload = JSON.parse(Buffer.from(payloadSegment, 'base64url').toString('utf8'));
      expect(payload.sub).toBe('bob@example.com');
    });
  });
});
