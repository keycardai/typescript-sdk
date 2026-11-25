import { jest } from '@jest/globals';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { ApplicationCredential } from './credentials.js';
import { ConfigurationError, HTTPError, OAuthError } from './errors.js';
import * as oauth from './index.js';
import { WebIdentity } from './server/webIdentity.js';

const { revokeToken } = oauth;
type RevokeTokenOptions = Parameters<typeof revokeToken>[2];
const ISSUER = 'https://zone.example.com';
const ENDPOINT = `${ISSUER}/custom/revoke`;
const METADATA = { issuer: ISSUER, revocation_endpoint: ENDPOINT };
const CLIENT_ID = 'client:id';
const TOKEN = 'refresh+token/=';
const JWT_BEARER = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

describe('revokeToken', () => {
  let transport: ReturnType<typeof jest.fn<typeof fetch>>;
  let options: RevokeTokenOptions;

  beforeEach(() => {
    transport = jest.fn<typeof fetch>().mockResolvedValue(new Response(null, { status: 200 }));
    options = { clientId: CLIENT_ID, metadata: METADATA, fetch: transport };
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

  function oauthFailure(status: number, error: string, description: string, token = TOKEN) {
    transport.mockResolvedValueOnce(Response.json({
      error, error_description: description, reason: 'server_reason',
    }, { status }));
    return revokeToken(ISSUER, token, options);
  }

  it('token revocation row 1: posts only the token, default hint and public client ID to the discovered endpoint', async () => {
    transport.mockResolvedValueOnce(Response.json(METADATA));

    await revokeToken(ISSUER, TOKEN, { ...options, metadata: undefined });

    expect(transport).toHaveBeenCalledTimes(2);
    expect(String(transport.mock.calls[0]![0])).toBe(`${ISSUER}/.well-known/oauth-authorization-server`);
    const post = request(1);
    expect(post.url).toBe(ENDPOINT);
    expect(post.method).toBe('POST');
    expect(post.headers.get('content-type')).toBe('application/x-www-form-urlencoded');
    expect(post.headers.has('authorization')).toBe(false);
    expect(post.form).toEqual({ token: TOKEN, token_type_hint: 'refresh_token', client_id: CLIENT_ID });
  });

  it('token revocation row 2: uses HTTP Basic rather than a duplicate client ID in the form', async () => {
    await revokeToken(ISSUER, TOKEN, { ...options, clientSecret: 'secret+value' });

    const post = request();
    expect(post.headers.get('authorization')).toBe(`Basic ${btoa('client%3Aid:secret%2Bvalue')}`);
    expect(post.form).toEqual({ token: TOKEN, token_type_hint: 'refresh_token' });
  });

  it('token revocation row 3: merges credential auth and signs the zone issuer as the sole audience', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'oauth-revocation-'));
    try {
      const credential = new WebIdentity({ clientId: CLIENT_ID, storageDir: dir });
      const authenticate = credential.clientAuthentication.bind(credential);
      const clientAuthentication = jest.spyOn(credential, 'clientAuthentication').mockImplementation(async (...args) => {
        const auth = await authenticate(...args);
        return { ...auth, headers: { 'X-Client-Auth': 'credential-header' } };
      });
      const explicitIssuer = `${ISSUER}/`;

      await revokeToken(explicitIssuer, TOKEN, { ...options, clientId: undefined, credential });

      expect(clientAuthentication).toHaveBeenCalledWith(explicitIssuer, explicitIssuer);
      expect(clientAuthentication).toHaveBeenCalledTimes(1);
      const post = request();
      expect(post.headers.get('x-client-auth')).toBe('credential-header');
      const assertion = post.form.client_assertion;
      expect(post.form).toEqual({
        token: TOKEN, token_type_hint: 'refresh_token', client_assertion: expect.any(String),
        client_assertion_type: JWT_BEARER,
      });
      const claims = JSON.parse(Buffer.from(assertion.split('.')[1], 'base64url').toString('utf8'));
      expect(claims.aud).toBe(explicitIssuer);
      expect(claims.iss).toBe(CLIENT_ID);
      expect(claims.sub).toBe(CLIENT_ID);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('token revocation row 4: sends an explicit hint unchanged', async () => {
    await revokeToken(ISSUER, TOKEN, { ...options, tokenTypeHint: 'custom/type' });

    expect(request().form.token_type_hint).toBe('custom/type');
  });

  it.each(['known', 'unknown', 'expired', 'invalid', 'already-revoked'])(
    'token revocation row 5: succeeds without parsing an empty HTTP 200 for a %s token',
    async (token) => {
      const response = new Response(null, { status: 200 });
      const json = jest.spyOn(response, 'json');
      const text = jest.spyOn(response, 'text');
      transport.mockResolvedValueOnce(response);

      await expect(revokeToken(ISSUER, token, options)).resolves.toBeUndefined();
      expect(json).not.toHaveBeenCalled();
      expect(text).not.toHaveBeenCalled();
    },
  );

  it('token revocation row 6: rejects discovered metadata without an endpoint and never tries a fallback path', async () => {
    transport.mockResolvedValueOnce(Response.json({ issuer: ISSUER }));

    await expect(revokeToken(ISSUER, TOKEN, { ...options, metadata: undefined })).rejects.toThrow(ConfigurationError);
    expect(transport).toHaveBeenCalledTimes(1);
    expect(String(transport.mock.calls[0]![0])).toBe(`${ISSUER}/.well-known/oauth-authorization-server`);
  });

  it.each([42, 'not a URL'])('rejects an unusable discovered endpoint %p as a configuration error', async (endpoint) => {
    transport.mockResolvedValueOnce(Response.json({ issuer: ISSUER, revocation_endpoint: endpoint }));

    await expect(revokeToken(ISSUER, TOKEN, { ...options, metadata: undefined })).rejects.toThrow(ConfigurationError);
    expect(transport).toHaveBeenCalledTimes(1);
    expect(String(transport.mock.calls[0]![0])).toBe(`${ISSUER}/.well-known/oauth-authorization-server`);
  });

  it('rejects an HTTP endpoint advertised by HTTPS discovery before sending the token or secret', async () => {
    transport.mockResolvedValueOnce(Response.json({
      issuer: ISSUER,
      revocation_endpoint: 'http://zone.example.com/custom/revoke',
    }));

    await expect(revokeToken(ISSUER, TOKEN, {
      ...options, clientSecret: 'secret', metadata: undefined,
    })).rejects.toThrow(ConfigurationError);
    expect(transport).toHaveBeenCalledTimes(1);
    expect(String(transport.mock.calls[0]![0])).toBe(`${ISSUER}/.well-known/oauth-authorization-server`);
  });

  it('rejects an HTTP endpoint in supplied metadata without making a request', async () => {
    const metadata = { issuer: 'http://zone.example.com', revocation_endpoint: 'http://zone.example.com/custom/revoke' };

    await expect(revokeToken(undefined, TOKEN, { ...options, metadata })).rejects.toThrow(ConfigurationError);
    expect(transport).not.toHaveBeenCalled();
  });

  it.each([
    { status: 401, code: 'invalid_client', description: 'Client authentication failed', retryable: false },
    { status: 400, code: 'invalid_grant', description: 'Token belongs to another client', retryable: true },
    { status: 400, code: 'unsupported_token_type', description: 'Token type not supported', retryable: true },
  ])('token revocation row 7: preserves $code, description, reason and status with retryable $retryable', async ({ status, code, description, retryable }) => {
    const failure = oauthFailure(status, code, description);

    await expect(failure).rejects.toBeInstanceOf(OAuthError);
    await expect(failure).rejects.toMatchObject({ errorCode: code, errorDescription: description, reason: 'server_reason', status, retryable });
    expect(transport).toHaveBeenCalledTimes(1);
  });

  it('token revocation row 8: reports a retryable transport failure without a hidden retry', async () => {
    const cause = new TypeError('connection refused');
    transport.mockRejectedValueOnce(cause);
    const failure = revokeToken(ISSUER, TOKEN, options);

    await expect(failure).rejects.toBeInstanceOf(HTTPError);
    await expect(failure).rejects.toMatchObject({ cause, retryable: true });
    expect(transport).toHaveBeenCalledTimes(1);
  });

  it('token revocation row 8: reports a retryable HTTP 503 without a hidden retry', async () => {
    transport.mockResolvedValueOnce(new Response('Unavailable', { status: 503 }));
    const failure = revokeToken(ISSUER, TOKEN, options);

    await expect(failure).rejects.toBeInstanceOf(HTTPError);
    await expect(failure).rejects.toMatchObject({ status: 503, retryable: true });
    expect(transport).toHaveBeenCalledTimes(1);
  });

  const credentialWithoutAuth: ApplicationCredential = {
    getAuth: () => null,
    prepareTokenExchangeRequest: jest.fn<ApplicationCredential['prepareTokenExchangeRequest']>(),
  };
  const credential = {
    ...credentialWithoutAuth,
    clientAuthentication: jest.fn<NonNullable<ApplicationCredential['clientAuthentication']>>(),
  };

  it.each([
    { name: 'a credential with a client ID', auth: { credential, clientId: CLIENT_ID } },
    { name: 'a credential with a secret', auth: { credential, clientSecret: 'secret' } },
    { name: 'a credential without client authentication', auth: { credential: credentialWithoutAuth } },
    { name: 'a secret without a client ID', auth: { clientSecret: 'secret' } },
    { name: 'no client ID or credential', auth: {} },
  ])('token revocation row 9: rejects $name before discovery', async ({ auth }) => {
    await expect(revokeToken(ISSUER, TOKEN, { ...auth, fetch: transport })).rejects.toThrow(ConfigurationError);
    expect(transport).not.toHaveBeenCalled();
  });

  it('token revocation row 10: uses supplied metadata without discovering the issuer', async () => {
    await revokeToken(undefined, TOKEN, options);

    expect(transport).toHaveBeenCalledTimes(1);
    expect(request().url).toBe(ENDPOINT);
  });

  it.each(['', undefined])('token revocation row 11: rejects a missing or empty token (%p) before discovery', async (token) => {
    await expect(revokeToken(ISSUER, token!, { ...options, metadata: undefined })).rejects.toThrow(ConfigurationError);
    expect(transport).not.toHaveBeenCalled();
  });

  it.each(['invalid_grant', 'unsupported_token_type'])(
    'token revocation row 12: %s is retryable per the base table',
    async (code) => {
      await expect(oauthFailure(400, code, 'Token cannot be revoked')).rejects.toMatchObject({ retryable: true });
    },
  );

  it.each([
    { row: 13, description: 'Exchanged access token with act', claims: { iss: ISSUER, sid: 'session', act: { sub: 'actor' } } },
    { row: 14, description: 'Access token without sid', claims: { iss: ISSUER } },
    { row: 15, description: 'Recognized token type from another issuer', claims: { iss: 'https://other.example.com', sid: 'session' } },
  ])('token revocation row $row: HTTP 400 for $description yields unsupported_token_type', async ({ description, claims }) => {
    const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'at+jwt' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify(claims)).toString('base64url');
    const token = `${header}.${payload}.signature`;
    const failure = oauthFailure(400, 'unsupported_token_type', description, token);

    await expect(failure).rejects.toBeInstanceOf(OAuthError);
    await expect(failure).rejects.toMatchObject({
      errorCode: 'unsupported_token_type', errorDescription: description, status: 400,
    });
    expect(request().form.token).toBe(token);
  });

  it.each([429, 503])('gives HTTP %i precedence over a permanent OAuth error code', async (status) => {
    await expect(oauthFailure(status, 'invalid_client', 'Client authentication failed')).rejects.toMatchObject({
      status, errorCode: 'invalid_client', retryable: true,
    });
  });

  it('reports a non-OAuth HTTP 400 as non-retryable', async () => {
    transport.mockResolvedValueOnce(new Response(null, { status: 400 }));
    const failure = revokeToken(ISSUER, TOKEN, options);

    await expect(failure).rejects.toBeInstanceOf(HTTPError);
    await expect(failure).rejects.toMatchObject({ status: 400, retryable: false });
  });

  it('rejects an explicit issuer that does not match supplied metadata', async () => {
    await expect(revokeToken('https://other.example.com', TOKEN, options)).rejects.toThrow(ConfigurationError);
    expect(transport).not.toHaveBeenCalled();
  });

  it('preserves the caller abort reason', async () => {
    const controller = new AbortController();
    const reason = new Error('caller aborted');
    transport.mockImplementationOnce(async (_url, init) => {
      controller.abort(reason);
      init?.signal?.throwIfAborted();
      throw new Error('Expected an aborted fetch signal');
    });

    await expect(revokeToken(ISSUER, TOKEN, { ...options, signal: controller.signal })).rejects.toBe(reason);
    expect(transport).toHaveBeenCalledTimes(1);
  });

  it.each([
    { phase: 'discovery', metadata: undefined },
    { phase: 'revocation', metadata: METADATA },
  ])('reports an SDK deadline during $phase as retryable with the platform timeout as cause', async ({ metadata }) => {
    const controller = new AbortController();
    transport.mockImplementationOnce((_url, init) => new Promise<Response>((_resolve, reject) => {
      const signal = init!.signal!;
      signal.addEventListener('abort', () => reject(new DOMException('The request was aborted', 'AbortError')), { once: true });
    }));

    const failure = revokeToken(ISSUER, TOKEN, {
      ...options, metadata, signal: controller.signal, timeoutMs: 5,
    });

    await expect(failure).rejects.toBeInstanceOf(HTTPError);
    await expect(failure).rejects.toMatchObject({
      retryable: true,
      cause: { name: 'TimeoutError' },
    });
    expect(transport).toHaveBeenCalledTimes(1);
  });
});
