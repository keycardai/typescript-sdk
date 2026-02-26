import { jest } from '@jest/globals';

// Mock discovery module before importing keyring
const mockFetchMetadata = jest.fn<(issuer: string, options?: { signal?: AbortSignal }) => Promise<{ issuer: string; jwks_uri?: string }>>();
jest.unstable_mockModule('./discovery.js', () => ({
  fetchAuthorizationServerMetadata: mockFetchMetadata,
}));

// Mock global fetch for JWKS responses
const originalFetch = globalThis.fetch;
const mockFetch = jest.fn<typeof globalThis.fetch>();
globalThis.fetch = mockFetch;

// Import after mocking
const { JWKSOAuthKeyring } = await import('./keyring.js');

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

const TEST_ISSUER = 'https://auth.example.com';
const TEST_KID = 'test-key-1';
const TEST_JWKS_URI = 'https://auth.example.com/.well-known/jwks.json';

// RSA public key from RFC 7515 Appendix A.2
const RSA_PUBLIC_JWK = {
  kty: 'RSA',
  kid: TEST_KID,
  n: 'ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ',
  e: 'AQAB',
};

function makeJwksResponse(keys = [RSA_PUBLIC_JWK]) {
  return new Response(JSON.stringify({ keys }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

function setupMocks(jwksUri = TEST_JWKS_URI) {
  mockFetchMetadata.mockResolvedValue({
    issuer: TEST_ISSUER,
    jwks_uri: jwksUri,
  });
  mockFetch.mockResolvedValue(makeJwksResponse());
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

afterEach(() => {
  jest.clearAllMocks();
});

afterAll(() => {
  globalThis.fetch = originalFetch;
});

describe('JWKSOAuthKeyring', () => {

  describe('caching', () => {
    it('caches JWKS between consecutive calls', async () => {
      setupMocks();
      const keyring = new JWKSOAuthKeyring();

      const key1 = await keyring.key(TEST_ISSUER, TEST_KID);
      const key2 = await keyring.key(TEST_ISSUER, TEST_KID);

      expect(key1).toBe(key2);
      // Discovery: 1 call. JWKS fetch: 1 call. Total: 2 (not 4).
      expect(mockFetchMetadata).toHaveBeenCalledTimes(1);
      expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it('caches discovery across different kids from the same issuer', async () => {
      const kid2 = 'test-key-2';
      const publicJwk2 = { ...RSA_PUBLIC_JWK, kid: kid2 };

      mockFetchMetadata.mockResolvedValue({
        issuer: TEST_ISSUER,
        jwks_uri: TEST_JWKS_URI,
      });
      mockFetch.mockResolvedValue(makeJwksResponse([RSA_PUBLIC_JWK, publicJwk2]));

      const keyring = new JWKSOAuthKeyring();
      await keyring.key(TEST_ISSUER, TEST_KID);

      // Reset fetch mock to track second call
      mockFetch.mockClear();
      mockFetch.mockResolvedValue(makeJwksResponse([RSA_PUBLIC_JWK, publicJwk2]));

      await keyring.key(TEST_ISSUER, kid2);

      // Discovery should NOT be called again (cached)
      expect(mockFetchMetadata).toHaveBeenCalledTimes(1);
      // JWKS fetch should be called for the new kid
      expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it('re-fetches after key TTL expires', async () => {
      setupMocks();
      const keyring = new JWKSOAuthKeyring({ keyTtlMs: 0 });

      await keyring.key(TEST_ISSUER, TEST_KID);

      // With TTL=0, the key should be expired immediately
      mockFetch.mockResolvedValue(makeJwksResponse());
      await keyring.key(TEST_ISSUER, TEST_KID);

      // JWKS fetch should be called twice (cache expired)
      expect(mockFetch).toHaveBeenCalledTimes(2);
      // Discovery should still be cached (different TTL)
      expect(mockFetchMetadata).toHaveBeenCalledTimes(1);
    });

    it('re-discovers after discovery TTL expires', async () => {
      setupMocks();
      const keyring = new JWKSOAuthKeyring({ discoveryTtlMs: 0, keyTtlMs: 0 });

      await keyring.key(TEST_ISSUER, TEST_KID);

      mockFetchMetadata.mockResolvedValue({
        issuer: TEST_ISSUER,
        jwks_uri: TEST_JWKS_URI,
      });
      mockFetch.mockResolvedValue(makeJwksResponse());

      await keyring.key(TEST_ISSUER, TEST_KID);

      expect(mockFetchMetadata).toHaveBeenCalledTimes(2);
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });
  });

  describe('invalidate', () => {
    it('forces re-fetch after invalidation', async () => {
      setupMocks();
      const keyring = new JWKSOAuthKeyring();

      await keyring.key(TEST_ISSUER, TEST_KID);
      expect(mockFetchMetadata).toHaveBeenCalledTimes(1);
      expect(mockFetch).toHaveBeenCalledTimes(1);

      keyring.invalidate(TEST_ISSUER, TEST_KID);

      mockFetchMetadata.mockResolvedValue({
        issuer: TEST_ISSUER,
        jwks_uri: TEST_JWKS_URI,
      });
      mockFetch.mockResolvedValue(makeJwksResponse());

      await keyring.key(TEST_ISSUER, TEST_KID);
      expect(mockFetchMetadata).toHaveBeenCalledTimes(2);
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });
  });

  describe('concurrency', () => {
    it('deduplicates concurrent requests for the same key', async () => {
      setupMocks();
      const keyring = new JWKSOAuthKeyring();

      const [key1, key2, key3] = await Promise.all([
        keyring.key(TEST_ISSUER, TEST_KID),
        keyring.key(TEST_ISSUER, TEST_KID),
        keyring.key(TEST_ISSUER, TEST_KID),
      ]);

      expect(key1).toBe(key2);
      expect(key2).toBe(key3);
      expect(mockFetchMetadata).toHaveBeenCalledTimes(1);
      expect(mockFetch).toHaveBeenCalledTimes(1);
    });
  });

  describe('SSRF protection', () => {
    it('rejects jwks_uri with different origin than issuer', async () => {
      mockFetchMetadata.mockResolvedValue({
        issuer: TEST_ISSUER,
        jwks_uri: 'https://evil.example.com/.well-known/jwks.json',
      });
      const keyring = new JWKSOAuthKeyring();

      await expect(keyring.key(TEST_ISSUER, TEST_KID)).rejects.toThrow(
        /JWKS URI origin .* does not match issuer origin/,
      );
      // Should NOT have fetched the JWKS endpoint
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it('allows jwks_uri with same origin as issuer', async () => {
      setupMocks('https://auth.example.com/keys/jwks.json');
      const keyring = new JWKSOAuthKeyring();

      await expect(keyring.key(TEST_ISSUER, TEST_KID)).resolves.toBeDefined();
    });
  });

  describe('error handling', () => {
    it('throws when key kid is not found in JWKS', async () => {
      mockFetchMetadata.mockResolvedValue({
        issuer: TEST_ISSUER,
        jwks_uri: TEST_JWKS_URI,
      });
      mockFetch.mockResolvedValue(makeJwksResponse([]));

      const keyring = new JWKSOAuthKeyring();
      await expect(keyring.key(TEST_ISSUER, TEST_KID)).rejects.toThrow(
        `Failed to find key "${TEST_KID}" of "${TEST_ISSUER}"`,
      );
    });

    it('throws when discovery returns no jwks_uri', async () => {
      mockFetchMetadata.mockResolvedValue({
        issuer: TEST_ISSUER,
      });

      const keyring = new JWKSOAuthKeyring();
      await expect(keyring.key(TEST_ISSUER, TEST_KID)).rejects.toThrow(
        `No JSON Web Key Set available for "${TEST_ISSUER}"`,
      );
    });

    it('throws when JWKS fetch returns non-200', async () => {
      mockFetchMetadata.mockResolvedValue({
        issuer: TEST_ISSUER,
        jwks_uri: TEST_JWKS_URI,
      });
      mockFetch.mockResolvedValue(new Response('Not Found', { status: 404 }));

      const keyring = new JWKSOAuthKeyring();
      await expect(keyring.key(TEST_ISSUER, TEST_KID)).rejects.toThrow(
        /Failed to fetch JWKS.*HTTP 404/,
      );
    });

    it('retries after a failed fetch (does not cache errors)', async () => {
      mockFetchMetadata.mockResolvedValue({
        issuer: TEST_ISSUER,
        jwks_uri: TEST_JWKS_URI,
      });
      mockFetch.mockResolvedValueOnce(new Response('Error', { status: 500 }));

      const keyring = new JWKSOAuthKeyring();
      await expect(keyring.key(TEST_ISSUER, TEST_KID)).rejects.toThrow();

      // Second attempt should retry (inflight was cleaned up)
      mockFetch.mockResolvedValueOnce(makeJwksResponse());
      const key = await keyring.key(TEST_ISSUER, TEST_KID);
      expect(key).toBeDefined();
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });
  });

  describe('constructor defaults', () => {
    it('works with no arguments (backward compatible)', async () => {
      setupMocks();
      const keyring = new JWKSOAuthKeyring();
      const key = await keyring.key(TEST_ISSUER, TEST_KID);
      expect(key).toBeDefined();
    });

    it('accepts custom TTL options', async () => {
      setupMocks();
      const keyring = new JWKSOAuthKeyring({
        keyTtlMs: 1000,
        discoveryTtlMs: 2000,
        fetchTimeoutMs: 5000,
      });
      const key = await keyring.key(TEST_ISSUER, TEST_KID);
      expect(key).toBeDefined();
    });
  });

  describe('fetch timeouts', () => {
    it('passes AbortSignal to discovery fetch', async () => {
      setupMocks();
      const keyring = new JWKSOAuthKeyring({ fetchTimeoutMs: 5000 });
      await keyring.key(TEST_ISSUER, TEST_KID);

      // Verify that discovery was called with a signal option
      expect(mockFetchMetadata).toHaveBeenCalledWith(
        TEST_ISSUER,
        expect.objectContaining({ signal: expect.any(AbortSignal) }),
      );
    });

    it('passes AbortSignal to JWKS fetch', async () => {
      setupMocks();
      const keyring = new JWKSOAuthKeyring({ fetchTimeoutMs: 5000 });
      await keyring.key(TEST_ISSUER, TEST_KID);

      expect(mockFetch).toHaveBeenCalledWith(
        TEST_JWKS_URI,
        expect.objectContaining({ signal: expect.any(AbortSignal) }),
      );
    });
  });
});
