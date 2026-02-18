import { jest } from '@jest/globals';
import { mcpAuthMetadataRouter, AuthMetadataOptions, getOAuthProtectedResourceMetadataUrl } from './router.js';
import { OAuthMetadata } from '@modelcontextprotocol/sdk/shared/auth';
import express from 'express';
import supertest from 'supertest';

describe('MCP Auth Metadata Router', () => {

  const mockOAuthMetadata : OAuthMetadata = {
    issuer: 'https://auth.example.com',
  }

  describe('Router creation', () => {
    it('successfully creates router with valid options', () => {
      const options: AuthMetadataOptions = {
        oauthMetadata: mockOAuthMetadata,
      };

      expect(() => mcpAuthMetadataRouter(options)).not.toThrow();
    });
  });

  describe('Metadata endpoints', () => {
    let app: express.Express;

    beforeEach(() => {
      app = express();
      const options: AuthMetadataOptions = {
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

    it('returns OAuth protected resource metadata using self as authorization server for best compatibility with clients using MCP version 2025-03-26', async () => {
      const response = await supertest(app)
        .get('/.well-known/oauth-protected-resource')
        .set('Host', 'api.example.com')
        .set('MCP-Protocol-Version', '2025-03-26')

      expect(response.status).toBe(200);

      // Verify protected resource metadata
      expect(response.body).toStrictEqual({
        resource: 'http://api.example.com',
        authorization_servers: ['http://api.example.com'],
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
      const options: AuthMetadataOptions = {
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

      expect(global.fetch).toHaveBeenCalledWith('https://auth.example.com/.well-known/oauth-authorization-server');
      expect(response.status).toBe(200);
      expect(response.body).toStrictEqual({
        issuer: 'https://auth.example.com',
        authorization_endpoint: 'https://auth.example.com/authorize?resource=http%3A%2F%2Fapi.example.com',
        token_endpoint: 'https://auth.example.com/token',
        response_types_supported: ['code'],
        grant_types_supported: ['authorization_code', 'refresh_token'],
        code_challenge_methods_supported: ['S256'],
        token_endpoint_auth_methods_supported: ['client_secret_post']
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
