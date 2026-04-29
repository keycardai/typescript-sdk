import { z } from "zod";
import { fetchAuthorizationServerMetadata } from "./discovery.js";

export interface OAuthKeyring {
  key(issuer: string, kid: string): Promise<CryptoKey>
}

export type IdentifiableKey = {
  key: CryptoKey;
  issuer: string;
  kid: string;
};

export interface PrivateKeyring {
  key(usage: string): Promise<IdentifiableKey>
}

export interface JWKSOAuthKeyringOptions {
  /** TTL for cached CryptoKeys. Default: 5 minutes. */
  keyTtlMs?: number;
  /** TTL for cached discovery (issuer → jwks_uri) mappings. Default: 1 hour. */
  discoveryTtlMs?: number;
  /** Timeout for both discovery and JWKS fetch requests. Default: 10 seconds. */
  fetchTimeoutMs?: number;
}

const JWKSchema = z.object({
  kty: z.string(),
  alg: z.string().optional(),
  use: z.string().optional(),
  kid: z.string().optional(),
});

const RSAJWKSchema = JWKSchema.extend({
  n: z.string(),
  e: z.string(),
});

const ECJWKSchema = JWKSchema.extend({
  crv: z.string(),
  x: z.string(),
  y: z.string(),
});

const JWKSetSchema = z.object({
  keys: z.array(z.union([RSAJWKSchema, ECJWKSchema])),
});

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

interface CacheEntry<T> {
  value: T;
  expiresAt: number;
}

const DEFAULT_KEY_TTL_MS = 5 * 60 * 1000;        // 5 minutes
const DEFAULT_DISCOVERY_TTL_MS = 60 * 60 * 1000;  // 1 hour
const DEFAULT_FETCH_TIMEOUT_MS = 10_000;           // 10 seconds

function assertSameOrigin(issuer: string, jwksUri: string): void {
  const issuerOrigin = new URL(issuer).origin;
  const jwksOrigin = new URL(jwksUri).origin;
  if (issuerOrigin !== jwksOrigin) {
    throw new Error(
      `JWKS URI origin "${jwksOrigin}" does not match issuer origin "${issuerOrigin}" for "${issuer}"`,
    );
  }
}

function keyCacheKey(issuer: string, kid: string): string {
  return `${issuer}::${kid}`;
}

// ---------------------------------------------------------------------------
// JWKSOAuthKeyring — two-level cached keyring
// ---------------------------------------------------------------------------

export class JWKSOAuthKeyring implements OAuthKeyring {
  #keyTtlMs: number;
  #discoveryTtlMs: number;
  #fetchTimeoutMs: number;

  #discoveryCache = new Map<string, CacheEntry<string>>();
  #keyCache = new Map<string, CacheEntry<CryptoKey>>();

  #discoveryInflight = new Map<string, Promise<string>>();
  #keyInflight = new Map<string, Promise<CryptoKey>>();

  constructor(options?: JWKSOAuthKeyringOptions) {
    this.#keyTtlMs = options?.keyTtlMs ?? DEFAULT_KEY_TTL_MS;
    this.#discoveryTtlMs = options?.discoveryTtlMs ?? DEFAULT_DISCOVERY_TTL_MS;
    this.#fetchTimeoutMs = options?.fetchTimeoutMs ?? DEFAULT_FETCH_TIMEOUT_MS;
  }

  async key(issuer: string, kid: string): Promise<CryptoKey> {
    const cacheKey = keyCacheKey(issuer, kid);
    const cached = this.#getCached(this.#keyCache, cacheKey);
    if (cached) {
      return cached;
    }

    const jwksUri = await this.#resolveJwksUri(issuer);
    return this.#resolveKey(issuer, kid, jwksUri, cacheKey);
  }

  invalidate(issuer: string, kid: string): void {
    const cacheKey = keyCacheKey(issuer, kid);
    this.#keyCache.delete(cacheKey);
    this.#keyInflight.delete(cacheKey);
    this.#discoveryCache.delete(issuer);
    this.#discoveryInflight.delete(issuer);
  }

  /**
   * Drops all cached keys, JWKS URI discoveries, and inflight resolutions.
   * Use after a global key rotation when targeted `invalidate(issuer, kid)`
   * is impractical. Subsequent `key()` calls re-discover and re-fetch.
   */
  clear(): void {
    this.#keyCache.clear();
    this.#keyInflight.clear();
    this.#discoveryCache.clear();
    this.#discoveryInflight.clear();
  }

  // -------------------------------------------------------
  // Discovery resolution with cache + dedup
  // -------------------------------------------------------

  async #resolveJwksUri(issuer: string): Promise<string> {
    const cached = this.#getCached(this.#discoveryCache, issuer);
    if (cached) {
      return cached;
    }

    const inflight = this.#discoveryInflight.get(issuer);
    if (inflight) {
      return inflight;
    }

    const promise = (async () => {
      try {
        const metadata = await fetchAuthorizationServerMetadata(issuer, {
          signal: AbortSignal.timeout(this.#fetchTimeoutMs),
        });
        if (!metadata.jwks_uri) {
          throw new Error(`No JSON Web Key Set available for "${issuer}"`);
        }

        assertSameOrigin(issuer, metadata.jwks_uri);

        this.#discoveryCache.set(issuer, {
          value: metadata.jwks_uri,
          expiresAt: Date.now() + this.#discoveryTtlMs,
        });

        return metadata.jwks_uri;
      } finally {
        this.#discoveryInflight.delete(issuer);
      }
    })();

    this.#discoveryInflight.set(issuer, promise);
    return promise;
  }

  // -------------------------------------------------------
  // Key resolution with cache + dedup
  // -------------------------------------------------------

  async #resolveKey(
    issuer: string,
    kid: string,
    jwksUri: string,
    cacheKey: string,
  ): Promise<CryptoKey> {
    const inflight = this.#keyInflight.get(cacheKey);
    if (inflight) {
      return inflight;
    }

    const promise = (async () => {
      try {
        const response = await fetch(jwksUri, {
          signal: AbortSignal.timeout(this.#fetchTimeoutMs),
        });
        if (!response.ok) {
          throw new Error(
            `Failed to fetch JWKS from "${jwksUri}" for "${issuer}" (HTTP ${response.status})`,
          );
        }

        const json = await response.json();
        const jwkSet = JWKSetSchema.parse(json);
        const jwk = jwkSet.keys.find((jwk) => jwk.kid === kid);
        if (!jwk) {
          throw new Error(`Failed to find key "${kid}" of "${issuer}"`);
        }

        // TODO: make this more robust to uses and algs
        const key = await crypto.subtle.importKey(
          'jwk',
          jwk,
          {
            name: 'RSASSA-PKCS1-v1_5',
            hash: { name: 'SHA-256' },
          },
          true,
          ['verify'],
        );

        this.#keyCache.set(cacheKey, {
          value: key,
          expiresAt: Date.now() + this.#keyTtlMs,
        });

        return key;
      } finally {
        this.#keyInflight.delete(cacheKey);
      }
    })();

    this.#keyInflight.set(cacheKey, promise);
    return promise;
  }

  // -------------------------------------------------------
  // Generic cache lookup with TTL check
  // -------------------------------------------------------

  #getCached<T>(cache: Map<string, CacheEntry<T>>, key: string): T | undefined {
    const entry = cache.get(key);
    if (!entry) {
      return undefined;
    }
    if (Date.now() >= entry.expiresAt) {
      cache.delete(key);
      return undefined;
    }
    return entry.value;
  }
}
