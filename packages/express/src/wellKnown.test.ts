import { jest } from '@jest/globals';
import express from 'express';
import request from 'supertest';
import { keycardMetadataRouter } from './wellKnown.js';

const ISSUER = 'https://zone.keycard.cloud';

type FetchInput = Parameters<typeof fetch>[0];

describe('keycardMetadataRouter', () => {
  let originalFetch: typeof fetch;
  let fetchMock: jest.Mock;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
    fetchMock = jest.fn(async (_input: FetchInput) =>
      new Response(
        JSON.stringify({
          issuer: ISSUER,
          authorization_endpoint: `${ISSUER}/authorize`,
          token_endpoint: `${ISSUER}/token`,
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      ),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  function makeApp() {
    const app = express();
    app.use(keycardMetadataRouter({ issuer: ISSUER, resourceName: 'My API' }));
    return app;
  }

  it('serves /.well-known/oauth-protected-resource with CORS header', async () => {
    const app = makeApp();
    const res = await request(app).get('/.well-known/oauth-protected-resource');
    expect(res.status).toBe(200);
    expect(res.body.authorization_servers).toContain(ISSUER);
    expect(res.body.resource_name).toBe('My API');
    expect(res.headers['access-control-allow-origin']).toBe('*');
  });

  it('serves /.well-known/oauth-authorization-server proxied from issuer', async () => {
    const app = makeApp();
    const res = await request(app).get('/.well-known/oauth-authorization-server');
    expect(res.status).toBe(200);
    expect(res.body.issuer).toBe(ISSUER);
  });

  it('rewrites authorization_endpoint with a resource param', async () => {
    const app = makeApp();
    const res = await request(app).get('/.well-known/oauth-authorization-server');
    const authUrl = new URL(res.body.authorization_endpoint);
    expect(authUrl.searchParams.get('resource')).toBeTruthy();
  });

  it.each([
    '/.well-known/oauth-protected-resource',
    '/.well-known/oauth-authorization-server',
  ])('answers OPTIONS preflight on %s with 204 and CORS headers', async (path) => {
    const app = makeApp();
    const res = await request(app).options(path);
    expect(res.status).toBe(204);
    expect(res.headers['access-control-allow-origin']).toBe('*');
    expect(res.headers['access-control-allow-methods']).toBe('GET, OPTIONS');
    expect(res.headers['access-control-allow-headers']).toBe('Content-Type, MCP-Protocol-Version');
  });

  describe('jwks.json', () => {
    const publicJwks = {
      keys: [{ kty: 'OKP', crv: 'Ed25519', x: 'abc', kid: 'key-1' }],
    };

    it('serves /.well-known/jwks.json when publicJwks is supplied', async () => {
      const app = express();
      app.use(keycardMetadataRouter({ issuer: ISSUER, publicJwks }));

      const res = await request(app).get('/.well-known/jwks.json');
      expect(res.status).toBe(200);
      expect(res.headers['content-type']).toContain('application/json');
      expect(res.headers['access-control-allow-origin']).toBe('*');
      expect(res.body).toEqual(publicJwks);

      const preflight = await request(app).options('/.well-known/jwks.json');
      expect(preflight.status).toBe(204);
      expect(preflight.headers['access-control-allow-origin']).toBe('*');
    });

    it('returns 404 for /.well-known/jwks.json when publicJwks is not supplied', async () => {
      const app = makeApp();
      const res = await request(app).get('/.well-known/jwks.json');
      expect(res.status).toBe(404);
    });
  });
});
