import { jest } from '@jest/globals';
import { mcpAuthMetadataRouter, InferredAuthMetadataOptions, getOAuthProtectedResourceMetadataUrl } from './router.js';
import express from 'express';
import supertest from 'supertest';

describe('MCP Auth Metadata Router', () => {

  const mockOAuthMetadata = {
    issuer: 'https://auth.example.com',
  };

  describe('Router creation', () => {
    it('successfully creates router with valid options', () => {
      const options: InferredAuthMetadataOptions = {
        oauthMetadata: mockOAuthMetadata,
      };

      expect(() => mcpAuthMetadataRouter(options)).not.toThrow();
    });
  });

  it('metadata rows 7, 9a, 4a, 4b and integration 2: uses the configured resource and matching zone issuer', async () => {
    const app = express();
    app.use(mcpAuthMetadataRouter({
      oauthMetadata: { issuer: 'https://keycard.cloud' },
      resourceIdentifiersByZone: { a: 'https://api.example.com/mcp?q=1', b: 'https://api.example.com/b/mcp' },
    }));
    const document = '{\n  "authorization_endpoint": "https://a.keycard.cloud/authorize?resource=stale&keep=1"\n}\n';
    const fetch = jest.spyOn(globalThis, 'fetch').mockImplementation(async () => new Response(document));
    try {
      await supertest(app).get('/.well-known/oauth-protected-resource/mcp?q=1')
        .set('Host', 'internal.example')
        .expect(200).expect({ resource: 'https://api.example.com/mcp?q=1', authorization_servers: ['https://a.keycard.cloud'] });
      await supertest(app).get('/.well-known/oauth-protected-resource/mcp').expect(404);
      await supertest(app).get('/.well-known/oauth-protected-resource/b/mcp')
        .expect(200).expect({ resource: 'https://api.example.com/b/mcp', authorization_servers: ['https://b.keycard.cloud'] });
      await supertest(app).get('/.well-known/oauth-authorization-server/a').expect(200).expect(res => {
        expect(res.text).toBe(document);
      });
      await supertest(app).get('/.well-known/oauth-authorization-server').expect(404);
      await supertest(app).get('/.well-known/oauth-authorization-server/c').expect(404);
      await supertest(app).options('/.well-known/oauth-authorization-server/c').expect(404);
      expect(fetch).toHaveBeenCalledTimes(1);
      expect(fetch).toHaveBeenCalledWith('https://a.keycard.cloud/.well-known/oauth-authorization-server', expect.anything());
    } finally {
      fetch.mockRestore();
    }
  });

  it('metadata rows 8a, 8b and 9c: standalone validates explicit modes and publishes one shared document', async () => {
    const oauthMetadata = { issuer: 'https://keycard.cloud' };
    expect(() => mcpAuthMetadataRouter({ oauthMetadata, multiResource: true, allowAnyAudience: true })).toThrow();
    const app = express();
    app.use(mcpAuthMetadataRouter({ oauthMetadata, allowAnyAudience: true }));
    const resource = 'https://api.example.com/mcp';
    app.use(mcpAuthMetadataRouter({
      oauthMetadata, multiResource: true, resourceIdentifiersByZone: { a: resource, b: resource },
    }));
    await supertest(app).get('/.well-known/oauth-protected-resource').expect(404);
    await supertest(app).get('/.well-known/oauth-protected-resource/mcp')
      .expect(200).expect({ resource, authorization_servers: ['https://a.keycard.cloud', 'https://b.keycard.cloud'] });
  });

  describe('Metadata endpoints', () => {
    let app: express.Express;

    beforeEach(() => {
      app = express();
      const options: InferredAuthMetadataOptions = {
        oauthMetadata: mockOAuthMetadata,
        serviceDocumentationUrl: new URL('https://docs.example.com'),
        scopesSupported: ['read', 'write'],
        resourceName: 'Test API'
      };
      app.use(mcpAuthMetadataRouter(options));
    });

    afterEach(() => {
      jest.restoreAllMocks();
    });

    it('returns the configured issuer in authorization_servers regardless of the MCP-Protocol-Version header', async () => {
      const response = await supertest(app)
        .get('/.well-known/oauth-protected-resource')
        .set('Host', 'api.example.com')
        .set('MCP-Protocol-Version', '2025-03-26')

      expect(response.status).toBe(200);

      // Verify protected resource metadata
      expect(response.body).toStrictEqual({
        resource: 'http://api.example.com',
        authorization_servers: ['https://auth.example.com'],
        scopes_supported: ['read', 'write'],
        resource_name: 'Test API',
        resource_documentation: 'https://docs.example.com/'
      });
    });

    it('returns OAuth protected resource metadata', async () => {
      const response = await supertest(app)
        .get('/.well-known/oauth-protected-resource')
        .set('Host', 'api.example.com');

      expect(response.status).toBe(200);

      // Verify protected resource metadata
      expect(response.body).toStrictEqual({
        resource: 'http://api.example.com',
        authorization_servers: ['https://auth.example.com'],
        scopes_supported: ['read', 'write'],
        resource_name: 'Test API',
        resource_documentation: 'https://docs.example.com/'
      });
    });

    it('returns OAuth protected resource metadata for resource with path', async () => {
      const response = await supertest(app)
        .get('/.well-known/oauth-protected-resource/mcp')
        .set('Host', 'api.example.com');

      expect(response.status).toBe(200);

      // Verify protected resource metadata
      expect(response.body).toStrictEqual({
        resource: 'http://api.example.com/mcp',
        authorization_servers: ['https://auth.example.com'],
        scopes_supported: ['read', 'write'],
        resource_name: 'Test API',
        resource_documentation: 'https://docs.example.com/'
      });
    });

    it('returns OAuth protected resource metadata for resource with query', async () => {
      const response = await supertest(app)
        .get('/.well-known/oauth-protected-resource?k=v')
        .set('Host', 'api.example.com');

      expect(response.status).toBe(200);

      // Verify protected resource metadata
      expect(response.body).toStrictEqual({
        resource: 'http://api.example.com?k=v',
        authorization_servers: ['https://auth.example.com'],
        scopes_supported: ['read', 'write'],
        resource_name: 'Test API',
        resource_documentation: 'https://docs.example.com/'
      });
    });

    it('returns OAuth protected resource metadata for resource with path and query', async () => {
      const response = await supertest(app)
        .get('/.well-known/oauth-protected-resource/mcp?k=v')
        .set('Host', 'api.example.com');

      expect(response.status).toBe(200);

      // Verify protected resource metadata
      expect(response.body).toStrictEqual({
        resource: 'http://api.example.com/mcp?k=v',
        authorization_servers: ['https://auth.example.com'],
        scopes_supported: ['read', 'write'],
        resource_name: 'Test API',
        resource_documentation: 'https://docs.example.com/'
      });
    });

    it('returns OAuth protected resource metadata for resource with path with terminating slash', async () => {
      const response = await supertest(app)
        .get('/.well-known/oauth-protected-resource/mcp/')
        .set('Host', 'api.example.com');

      expect(response.status).toBe(200);

      // Verify protected resource metadata
      expect(response.body).toStrictEqual({
        resource: 'http://api.example.com/mcp/',
        authorization_servers: ['https://auth.example.com'],
        scopes_supported: ['read', 'write'],
        resource_name: 'Test API',
        resource_documentation: 'https://docs.example.com/'
      });
    });

    it('returns OAuth protected resource metadata for resource with path with terminating slash and query', async () => {
      const response = await supertest(app)
        .get('/.well-known/oauth-protected-resource/mcp/?k=v')
        .set('Host', 'api.example.com');

      expect(response.status).toBe(200);

      // Verify protected resource metadata
      expect(response.body).toStrictEqual({
        resource: 'http://api.example.com/mcp/?k=v',
        authorization_servers: ['https://auth.example.com'],
        scopes_supported: ['read', 'write'],
        resource_name: 'Test API',
        resource_documentation: 'https://docs.example.com/'
      });
    });

    it('works with minimal configuration', async () => {
      const minimalApp = express();
      const options: InferredAuthMetadataOptions = {
        oauthMetadata: mockOAuthMetadata,
      };
      minimalApp.use(mcpAuthMetadataRouter(options));

      const response = await supertest(minimalApp)
        .get('/.well-known/oauth-protected-resource')
        .set('Host', 'api.example.com');

      expect(response.status).toBe(200);
      expect(response.body).toStrictEqual({
        resource: 'http://api.example.com',
        authorization_servers: ['https://auth.example.com']
      });
    });

    it('returns OAuth authorization server metadata', async () => {
      jest.spyOn(global, 'fetch').mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({
          issuer: 'https://auth.example.com',
          authorization_endpoint: 'https://auth.example.com/authorize',
          token_endpoint: 'https://auth.example.com/token',
          response_types_supported: ['code'],
          grant_types_supported: ['authorization_code', 'refresh_token'],
          code_challenge_methods_supported: ['S256'],
          token_endpoint_auth_methods_supported: ['client_secret_post']
        })
      });

      const response = await supertest(app)
        .get('/.well-known/oauth-authorization-server')
        .set('Host', 'api.example.com');

      expect(global.fetch).toHaveBeenCalledWith('https://auth.example.com/.well-known/oauth-authorization-server', { signal: expect.any(AbortSignal) });
      expect(response.status).toBe(200);
      expect(response.body).toStrictEqual({
        issuer: 'https://auth.example.com',
        authorization_endpoint: 'https://auth.example.com/authorize',
        token_endpoint: 'https://auth.example.com/token',
        response_types_supported: ['code'],
        grant_types_supported: ['authorization_code', 'refresh_token'],
        code_challenge_methods_supported: ['S256'],
        token_endpoint_auth_methods_supported: ['client_secret_post']
      });
    });

    it('passes an authorization_endpoint with an existing query through unchanged', async () => {
      const upstream = {
        issuer: 'https://auth.example.com',
        authorization_endpoint: 'https://auth.example.com/authorize?resource=stale&keep=1',
        token_endpoint: 'https://auth.example.com/token'
      };
      jest.spyOn(global, 'fetch').mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(upstream)
      } as Response);

      const response = await supertest(app)
        .get('/.well-known/oauth-authorization-server')
        .set('Host', 'api.example.com');

      expect(response.status).toBe(200);
      expect(response.body).toStrictEqual(upstream);
    });

    it('returns 502 when the upstream AS metadata response is not OK', async () => {
      jest.spyOn(global, 'fetch').mockResolvedValue({
        ok: false,
        status: 500,
        json: () => Promise.resolve({})
      } as Response);

      const response = await supertest(app)
        .get('/.well-known/oauth-authorization-server')
        .set('Host', 'api.example.com');

      expect(response.status).toBe(502);
      expect(response.body).toStrictEqual({
        error: 'Failed to fetch AS metadata from issuer'
      });
    });

    it('returns 502 when the upstream AS metadata fetch rejects', async () => {
      jest.spyOn(global, 'fetch').mockRejectedValue(new Error('network down'));

      const response = await supertest(app)
        .get('/.well-known/oauth-authorization-server')
        .set('Host', 'api.example.com');

      expect(response.status).toBe(502);
      expect(response.body).toStrictEqual({
        error: 'Failed to fetch AS metadata from issuer'
      });
    });
  });
});

describe('MCP Protected Resource Metadata URL', () => {

  it('should insert well-known URI after host', () => {
    const serverUrl = new URL('https://mcp.example.com')
    expect(getOAuthProtectedResourceMetadataUrl(serverUrl)).toBe('https://mcp.example.com/.well-known/oauth-protected-resource');
  });

  it('should insert well-known URI after host with terminating slash', () => {
    const serverUrl = new URL('https://mcp.example.com/')
    expect(getOAuthProtectedResourceMetadataUrl(serverUrl)).toBe('https://mcp.example.com/.well-known/oauth-protected-resource');
  });

  it('should insert well-known URI between host and path', () => {
    const serverUrl = new URL('https://mcp.example.com/mcp')
    expect(getOAuthProtectedResourceMetadataUrl(serverUrl)).toBe('https://mcp.example.com/.well-known/oauth-protected-resource/mcp');
  });

  it('should insert well-known URI between host and query', () => {
    const serverUrl = new URL('https://mcp.example.com?k=v')
    expect(getOAuthProtectedResourceMetadataUrl(serverUrl)).toBe('https://mcp.example.com/.well-known/oauth-protected-resource?k=v');
  });

  it('should insert well-known URI between host and path and query', () => {
    const serverUrl = new URL('https://mcp.example.com/mcp?k=v')
    expect(getOAuthProtectedResourceMetadataUrl(serverUrl)).toBe('https://mcp.example.com/.well-known/oauth-protected-resource/mcp?k=v');
  });

  it('should insert well-known URI between host and path with terminating slash', () => {
    const serverUrl = new URL('https://mcp.example.com/mcp/')
    expect(getOAuthProtectedResourceMetadataUrl(serverUrl)).toBe('https://mcp.example.com/.well-known/oauth-protected-resource/mcp/');
  });

  it('should insert well-known URI between host and path with terminating slash and query', () => {
    const serverUrl = new URL('https://mcp.example.com/mcp/?k=v')
    expect(getOAuthProtectedResourceMetadataUrl(serverUrl)).toBe('https://mcp.example.com/.well-known/oauth-protected-resource/mcp/?k=v');
  });

});
