import { jest } from '@jest/globals';
import express from 'express';
import request from 'supertest';
import { keycardMetadataRouter } from './wellKnown.js';
import { createKeycardMiddleware } from './middleware.js';

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

  it('includes a nonstandard port in resource when req.host strips it (Express 4 host semantics)', async () => {
    const app = express();
    // Express 4's req.host is an alias for req.hostname: no port. Shadow the
    // Express 5 getter to simulate that; the Host header still carries the port.
    app.use((req, _res, next) => {
      Object.defineProperty(req, 'host', { value: 'api.example.com' });
      next();
    });
    app.use(keycardMetadataRouter({ issuer: ISSUER }));

    const res = await request(app)
      .get('/.well-known/oauth-protected-resource')
      .set('Host', 'api.example.com:8443');
    expect(res.status).toBe(200);
    expect(res.body.resource).toBe('http://api.example.com:8443');
  });

  it('serves /.well-known/oauth-authorization-server proxied from issuer', async () => {
    const app = makeApp();
    const res = await request(app).get('/.well-known/oauth-authorization-server');
    expect(res.status).toBe(200);
    expect(res.body.issuer).toBe(ISSUER);
  });

  it('passes the upstream authorization_endpoint through unchanged, existing query included', async () => {
    const upstream = {
      issuer: ISSUER,
      authorization_endpoint: `${ISSUER}/authorize?resource=stale&keep=1`,
      token_endpoint: `${ISSUER}/token`,
    };
    fetchMock.mockImplementation(async () =>
      new Response(JSON.stringify(upstream), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
    );
    const app = makeApp();
    const res = await request(app).get('/.well-known/oauth-authorization-server');
    expect(res.status).toBe(200);
    expect(res.body).toStrictEqual(upstream);
    expect(res.body.authorization_endpoint).toBe(`${ISSUER}/authorize?resource=stale&keep=1`);
  });

  it('metadata rows 1, 7 and 9: exposes each configured document at its host-root path', async () => {
    const app = express();
    const identifiers = ['https://api.example.com', 'https://api.example.com/mcp?q=%2F'];
    for (const resourceIdentifier of identifiers) {
      app.use(keycardMetadataRouter({ issuer: ISSUER, resourceIdentifier }));
    }
    for (const [i, suffix] of ['', '/mcp?q=%2F'].entries()) {
      await request(app).get('/.well-known/oauth-protected-resource' + suffix)
        .set('Host', 'internal.example').set('MCP-Protocol-Version', '2025-03-26')
        .expect(200).expect({ resource: identifiers[i], authorization_servers: [ISSUER] });
    }
    await request(app).get('/.well-known/oauth-protected-resource/mcp').expect(404);
  });

  it.each([{ resourceIdentifier: 'urn:example:service' }, { multiResource: true }, { allowAnyAudience: true }])(
    'metadata rows 8 and 8a: verifier-only mode %j omits protected-resource discovery',
    async mode => {
      const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
      try {
        const app = express();
        app.use(keycardMetadataRouter({ issuer: ISSUER, publicJwks: { keys: [] }, ...mode }));
        expect(warn).not.toHaveBeenCalled();
        await request(app).get('/.well-known/oauth-protected-resource').expect(404);
        await request(app).get('/.well-known/oauth-authorization-server').expect(200);
        await request(app).get('/.well-known/jwks.json').expect(200);
      } finally {
        warn.mockRestore();
      }
    },
  );

  it('metadata rows 4a, 4b, 9a and integration 2: the proxy and documents use the same configured issuer set', async () => {
    const upstream = '{\n  "authorization_endpoint": "https://auth.example.com/authorize?resource=stale&keep=1"\n}\n';
    fetchMock.mockImplementation(async () => new Response(upstream));
    const app = express();
    const resourceIdentifiersByZone = { z_abc123: 'https://api.example.com/a/mcp', b: 'https://api.example.com/b/mcp' };
    app.use(keycardMetadataRouter({ issuer: 'http://keycard.cloud:8443', resourceIdentifiersByZone }));
    for (const [zone, resource] of Object.entries(resourceIdentifiersByZone)) {
      const issuer = `http://${zone}.keycard.cloud:8443`;
      await request(app).get('/.well-known/oauth-protected-resource' + new URL(resource).pathname)
        .expect(200).expect({ resource, authorization_servers: [issuer] });
      await request(app).get(`/.well-known/oauth-authorization-server/${zone}`).expect(200).expect(res => {
        expect(res.text).toBe(upstream);
      });
      expect(fetchMock).toHaveBeenLastCalledWith(issuer + '/.well-known/oauth-authorization-server', expect.anything());
    }
    await request(app).get('/.well-known/oauth-authorization-server').expect(404);
    await request(app).get('/.well-known/oauth-authorization-server/c').expect(404);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('routes same-path metadata by Host with or without the default port', async () => {
    const app = express();
    const a = 'https://a.example.com/mcp';
    const b = 'http://b.example.com/mcp';
    app.enable('trust proxy');
    app.use(keycardMetadataRouter({ issuer: 'https://keycard.cloud', resourceIdentifiersByZone: { a, b } }));
    const path = '/.well-known/oauth-protected-resource/mcp';
    await request(app).get(path).set('Host', 'A.example.com:443').set('X-Forwarded-Host', 'b.example.com')
      .expect(200).expect({ resource: a, authorization_servers: ['https://a.keycard.cloud'] });
    await request(app).get(path).set('Host', 'b.example.com:80')
      .expect(200).expect({ resource: b, authorization_servers: ['https://b.keycard.cloud'] });
    await request(app).get(path).set('Host', 'a.example.com:8443').expect(404);
  });

  it('metadata row 9c: shared discovery advertises exactly the configured zones', async () => {
    const app = express();
    const resource = 'https://api.example.com/mcp';
    app.use(keycardMetadataRouter({
      issuer: 'https://keycard.cloud', multiResource: true, resourceIdentifiersByZone: { a: resource, b: resource },
    }));
    await request(app).get('/.well-known/oauth-protected-resource/mcp').expect(200)
      .expect({ resource, authorization_servers: ['https://a.keycard.cloud', 'https://b.keycard.cloud'] });
  });

  it('metadata rows 8b, 9b and 9d: rejects conflicting options and invalid discovery topology', () => {
    const resource = 'https://api.example.com';
    const zones = { a: resource, b: resource + '/mcp' };
    for (const invalid of [
      { multiResource: true, allowAnyAudience: true },
      { resourceIdentifier: resource, resourceIdentifiersByZone: zones },
      { resourceIdentifier: resource, multiResource: true },
      { resourceIdentifier: resource, allowAnyAudience: true },
      { resourceIdentifiersByZone: zones, allowAnyAudience: true },
      { resourceIdentifiersByZone: zones, multiResource: true },
      { resourceIdentifiersByZone: zones, issuer: '' },
      { resourceIdentifiersByZone: { a: resource, b: resource + '/' } },
    ]) expect(() => keycardMetadataRouter({ issuer: ISSUER, ...invalid })).toThrow();
  });

  it('metadata row 8c: standalone router warns once and preserves legacy discovery', async () => {
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      const app = express();
      app.use(keycardMetadataRouter({ issuer: ISSUER, multiResource: false, allowAnyAudience: false }));
      for (const host of ['a.example.com', 'b.example.com']) {
        await request(app).get('/.well-known/oauth-protected-resource').set('Host', host)
          .expect(200).expect({ resource: 'http://' + host, authorization_servers: [ISSUER] });
      }
      expect(warn).toHaveBeenCalledTimes(1);
      expect(warn).toHaveBeenCalledWith(expect.stringContaining('resource_identifier'));
    } finally {
      warn.mockRestore();
    }
  });

  it('bearer rows 7, 14 and 14a: warns once per legacy configuration', async () => {
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      for (const audience of [undefined, 'resource', ['resource'], { a: 'resource' }]) {
        warn.mockClear();
        const app = express();
        const config = createKeycardMiddleware({ zoneUrl: ISSUER, audience });
        app.use(config.metadataRouter());
        app.use(config.requireBearerAuth());
        await request(app).get('/.well-known/oauth-protected-resource').expect(200);
        await request(app).get('/mcp').expect(401).expect('WWW-Authenticate', /resource_metadata/);
        expect(warn).toHaveBeenCalledTimes(1);
        expect(warn).toHaveBeenCalledWith(expect.stringContaining('resource_identifier'));
        if (audience && !Array.isArray(audience) && typeof audience !== 'string') {
          expect(warn).toHaveBeenCalledWith(expect.stringContaining('resource_identifiers_by_zone'));
        }
      }
    } finally {
      warn.mockRestore();
    }
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
