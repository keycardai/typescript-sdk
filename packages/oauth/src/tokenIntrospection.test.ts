import { jest } from '@jest/globals';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  ClientSecret, ConfigurationError, OAuthError, TokenIntrospectionHTTPError,
  introspectToken, type ApplicationCredential, type IntrospectTokenOptions, type TokenIntrospection,
} from './index.js';
import { WebIdentity } from './server/webIdentity.js';

const ISSUER = 'https://zone.example.com';
const ENDPOINT = `${ISSUER}/custom/introspect`;
const DISCOVERY = `${ISSUER}/.well-known/oauth-authorization-server`;
const METADATA = { issuer: ISSUER, introspection_endpoint: ENDPOINT };
const CLIENT_ID = 'client:id';
const SECRET = 'secret+value';
const TOKEN = 'token+value/=';

describe('introspectToken', () => {
  let transport: ReturnType<typeof jest.fn<typeof fetch>>;
  let options: IntrospectTokenOptions;

  beforeEach(() => {
    transport = jest.fn<typeof fetch>().mockImplementation(async () => Response.json({ active: false }));
    options = { credential: new ClientSecret(CLIENT_ID, SECRET), metadata: METADATA, fetch: transport };
  });

  function request(index = 0) {
    const [target, init] = transport.mock.calls[index]!;
    return {
      url: String(target),
      method: init?.method,
      headers: new Headers(init?.headers),
      form: Object.fromEntries(new URLSearchParams(String(init?.body))),
    };
  }

  it('token introspection row 1: posts the token to the discovered endpoint with HTTP Basic authentication', async () => {
    transport.mockResolvedValueOnce(Response.json(METADATA));

    await introspectToken(ISSUER, TOKEN, { ...options, metadata: undefined });

    expect(transport).toHaveBeenCalledTimes(2);
    expect(request().url).toBe(DISCOVERY);
    const post = request(1);
    expect(post.url).toBe(ENDPOINT);
    expect(post.method).toBe('POST');
    expect(post.headers.get('content-type')).toBe('application/x-www-form-urlencoded');
    expect(post.headers.get('authorization')).toBe(`Basic ${btoa('client%3Aid:secret%2Bvalue')}`);
    expect(post.form).toEqual({ token: TOKEN });
  });

  it('token introspection row 2: sends the credential headers and a JWT assertion with the issuer as its sole audience', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'oauth-introspection-'));
    try {
      const credential = new WebIdentity({ clientId: CLIENT_ID, storageDir: dir });
      const authenticate = credential.clientAuthentication.bind(credential);
      const clientAuthentication = jest.spyOn(credential, 'clientAuthentication').mockImplementation(async (...args) => {
        const auth = await authenticate(...args);
        return { ...auth, headers: { 'X-Client-Auth': 'credential-header' } };
      });
      const explicitIssuer = `${ISSUER}/`;

      await introspectToken(explicitIssuer, TOKEN, { ...options, credential });

      expect(clientAuthentication).toHaveBeenCalledTimes(1);
      expect(clientAuthentication).toHaveBeenCalledWith(explicitIssuer, explicitIssuer);
      const post = request();
      expect(post.headers.get('x-client-auth')).toBe('credential-header');
      expect(post.form).toEqual({
        token: TOKEN,
        client_assertion: expect.any(String),
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      });
      const claims = JSON.parse(Buffer.from(post.form.client_assertion.split('.')[1], 'base64url').toString('utf8'));
      expect(claims.aud).toBe(explicitIssuer);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('token introspection row 3: types active access-token claims and parses scopes', async () => {
    const claims = {
      active: true, token_type: 'Bearer', iss: ISSUER, sub: 'subject', client_id: CLIENT_ID,
      aud: ['https://api.example.com', ISSUER], scope: 'read  write', sid: 'session', jti: 'token-id',
      iat: 1_700_000_000, exp: 1_700_000_600,
    };
    transport.mockResolvedValueOnce(Response.json(claims));

    const result: TokenIntrospection = await introspectToken(ISSUER, TOKEN, options);

    if (!result.active) throw new Error('Expected an active token');
    const scopes: string[] | undefined = result.scope;
    expect(scopes).toEqual(['read', 'write']);
    expect(result).toEqual({ ...claims, scope: ['read', 'write'] });
  });

  it.each([{ active: false }, { active: false, scope: 'read', sub: 'subject' }])(
    'token introspection row 4: returns only active: false for an inactive token',
    async (body) => {
      transport.mockResolvedValueOnce(Response.json(body));
      await expect(introspectToken(ISSUER, TOKEN, options)).resolves.toEqual({ active: false });
    },
  );

  it.each([undefined, 'http://zone.example.com/introspect', 'not a URL'])(
    'token introspection row 5: rejects a missing or unusable endpoint (%p) without a path fallback',
    async (endpoint) => {
      transport.mockResolvedValueOnce(Response.json({ issuer: ISSUER, introspection_endpoint: endpoint }));

      await expect(introspectToken(ISSUER, TOKEN, { ...options, metadata: undefined })).rejects.toThrow(ConfigurationError);
      expect(transport).toHaveBeenCalledTimes(1);
      expect(request().url).toBe(DISCOVERY);
    },
  );

  it.each([
    { status: 401, code: 'invalid_client', description: 'Authentication failed', retryable: false },
    { status: 400, code: 'invalid_request', description: 'Malformed request', retryable: true },
  ])('token introspection row 6: preserves HTTP $status $code and its retryability', async ({ status, code, description, retryable }) => {
    transport.mockResolvedValueOnce(Response.json({
      error: code, error_description: description, reason: 'server_reason',
    }, { status }));

    const failure = introspectToken(ISSUER, TOKEN, options);

    await expect(failure).rejects.toBeInstanceOf(OAuthError);
    await expect(failure).rejects.toMatchObject({
      errorCode: code, errorDescription: description, reason: 'server_reason', status, retryable,
    });
    expect(transport).toHaveBeenCalledTimes(1);
  });

  it('token introspection row 7: reports a retryable transport failure without retrying', async () => {
    const cause = new TypeError('connection refused');
    transport.mockRejectedValueOnce(cause);

    const failure = introspectToken(ISSUER, TOKEN, options);

    await expect(failure).rejects.toBeInstanceOf(TokenIntrospectionHTTPError);
    await expect(failure).rejects.toMatchObject({ cause, retryable: true });
    expect(transport).toHaveBeenCalledTimes(1);
  });

  it('token introspection row 7: reports a retryable HTTP 503 without retrying', async () => {
    transport.mockResolvedValueOnce(new Response('Unavailable', { status: 503, headers: { 'Retry-After': '5' } }));

    const failure = introspectToken(ISSUER, TOKEN, options);

    await expect(failure).rejects.toBeInstanceOf(TokenIntrospectionHTTPError);
    await expect(failure).rejects.toMatchObject({ status: 503, retryable: true, retryAfter: '5' });
    expect(transport).toHaveBeenCalledTimes(1);
  });

  it('token introspection row 7: preserves a retryable OAuth server_error without retrying', async () => {
    transport.mockResolvedValueOnce(Response.json({ error: 'server_error' }, { status: 500 }));

    const failure = introspectToken(ISSUER, TOKEN, options);

    await expect(failure).rejects.toBeInstanceOf(OAuthError);
    await expect(failure).rejects.toMatchObject({ status: 500, errorCode: 'server_error', retryable: true });
    expect(transport).toHaveBeenCalledTimes(1);
  });

  it.each(['', '{', '{}', '{"active":"false"}'])(
    'token introspection row 8: reports an invalid response for body %p',
    async (body) => {
      transport.mockResolvedValueOnce(new Response(body));

      const failure = introspectToken(ISSUER, TOKEN, options);

      await expect(failure).rejects.toBeInstanceOf(OAuthError);
      await expect(failure).rejects.toMatchObject({ errorCode: 'invalid_response', status: 200, retryable: true });
    },
  );

  it('token introspection row 9: requests the same token twice without caching its status', async () => {
    transport.mockResolvedValueOnce(Response.json({ active: true }));

    await expect(introspectToken(ISSUER, TOKEN, options)).resolves.toEqual({ active: true });
    await expect(introspectToken(ISSUER, TOKEN, options)).resolves.toEqual({ active: false });
    expect(transport).toHaveBeenCalledTimes(2);
    expect(request().form).toEqual(request(1).form);
  });

  it('token introspection row 10: uses supplied metadata without discovering the issuer', async () => {
    await introspectToken(undefined, TOKEN, options);

    expect(transport).toHaveBeenCalledTimes(1);
    expect(request().url).toBe(ENDPOINT);
  });

  it('token introspection row 11: rejects credentials without client authentication before discovery', async () => {
    const credential: ApplicationCredential = {
      getAuth: () => null,
      prepareTokenExchangeRequest: jest.fn<ApplicationCredential['prepareTokenExchangeRequest']>(),
    };

    await expect(introspectToken(ISSUER, TOKEN, { ...options, metadata: undefined, credential })).rejects.toThrow(ConfigurationError);
    expect(transport).not.toHaveBeenCalled();
  });

  it.each(['', undefined])('token introspection row 12: rejects a missing or empty token (%p) before discovery', async (token) => {
    await expect(introspectToken(ISSUER, token!, { ...options, metadata: undefined })).rejects.toThrow(ConfigurationError);
    expect(transport).not.toHaveBeenCalled();
  });

  it('token introspection row 13: types the issuer and preserves unknown claims', async () => {
    const claims = {
      active: true, iss: ISSUER, act: { sub: 'actor' }, sub_profile: 'user',
      auth_time: 1_700_000_000, keycard_app_id: 'application',
    };
    transport.mockResolvedValueOnce(Response.json(claims));

    const result = await introspectToken(ISSUER, TOKEN, options);

    if (!result.active) throw new Error('Expected an active token');
    const issuer: string | undefined = result.iss;
    expect(issuer).toBe(ISSUER);
    expect(result).toEqual(claims);
  });

  it('token introspection row 14: returns an active refresh token without a token type', async () => {
    const claims = { active: true, aud: ISSUER, sub: 'user', sid: 'session' };
    transport.mockResolvedValueOnce(Response.json(claims));

    const result = await introspectToken(ISSUER, TOKEN, options);

    expect(result).toEqual(claims);
    expect(result).not.toHaveProperty('token_type');
  });

  it.each([' custom/type+value ', '', undefined])(
    'token introspection row 15: sends the hint %p unchanged when set and omits it otherwise',
    async (tokenTypeHint) => {
      await introspectToken(ISSUER, TOKEN, { ...options, tokenTypeHint });

      expect(request().form).toEqual(
        tokenTypeHint === undefined ? { token: TOKEN } : { token: TOKEN, token_type_hint: tokenTypeHint },
      );
    },
  );

  it('rejects an explicit issuer that does not match supplied metadata', async () => {
    await expect(introspectToken('https://other.example.com', TOKEN, options)).rejects.toThrow(ConfigurationError);
    expect(transport).not.toHaveBeenCalled();
  });

  it('does not follow a redirect from the introspection endpoint', async () => {
    transport.mockResolvedValueOnce(Response.redirect('https://other.example.com/introspect', 307));

    await expect(introspectToken(ISSUER, TOKEN, options)).rejects.toMatchObject({ status: 307, retryable: false });
    expect(transport.mock.calls[0]![1]?.redirect).toBe('manual');
    expect(transport).toHaveBeenCalledTimes(1);
  });

  it('preserves caller cancellation from the HTTP transport', async () => {
    const controller = new AbortController();
    const reason = new Error('caller aborted');
    transport.mockImplementationOnce(async (_url, init) => {
      controller.abort(reason);
      init?.signal?.throwIfAborted();
      throw new Error('Expected an aborted fetch signal');
    });

    await expect(introspectToken(ISSUER, TOKEN, { ...options, signal: controller.signal })).rejects.toBe(reason);
    expect(transport).toHaveBeenCalledTimes(1);
  });
});
