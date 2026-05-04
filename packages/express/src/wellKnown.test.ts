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
});
