import { z } from "zod";
import { fetchAuthorizationServerMetadata } from "./discovery.js";
import {
  HTTPError,
  JWKSDiscoveryError,
  JWKSFetchError,
  JWKSKeyNotFoundError,
  JWKSUriValidationError,
  OAuthError,
  ResponseBodyTooLargeError,
} from "./errors.js";
import { isTransientMetadataFailure, MetadataRetryCache } from "./metadataRetry.js";
import { discardResponseBody, readResponseText } from "./responseBody.js";

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
  /** Maximum number of cached keys before the oldest is evicted. Default: 256. */
  keyCacheMaxEntries?: number;
  /**
   * Minimum time between two JWKS fetches for one issuer when a token names a
   * `kid` the cached key set does not hold. A forged token can carry any
   * `kid`, so without this every such request costs a fetch from the zone.
   * A key that rotated in is picked up once this has passed. Default: 30 seconds.
   */
  jwksRefetchCooldownMs?: number;
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
type JWKSet = z.infer<typeof JWKSetSchema>;

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
const DEFAULT_KEY_CACHE_MAX_ENTRIES = 256;         // bound the key cache
const DEFAULT_JWKS_REFETCH_COOLDOWN_MS = 30_000;   // 30 seconds, as jose's remote JWKS

function assertSameOrigin(issuer: string, jwksUri: string): void {
  const issuerOrigin = new URL(issuer).origin;
  const jwksOrigin = new URL(jwksUri).origin;
  if (issuerOrigin !== jwksOrigin) {
    throw new JWKSUriValidationError(
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
  #keyCacheMaxEntries: number;

  #discoveryInflight = new Map<string, Promise<string>>();
  #discoveryRetry = new MetadataRetryCache();
  #keyInflight = new Map<string, Promise<CryptoKey>>();

  // The last key set fetched from each jwks_uri, with when it was fetched, so
  // a kid it holds needs no fetch and a kid it lacks refetches at most once
  // per cooldown.
  #jwksCache = new Map<string, CacheEntry<JWKSet> & { fetchedAt: number }>();
  #jwksInflight = new Map<string, Promise<JWKSet>>();
  #jwksRetry = new MetadataRetryCache();
  #generation = 0;
  #jwksRefetchCooldownMs: number;

  constructor(options?: JWKSOAuthKeyringOptions) {
    this.#keyTtlMs = options?.keyTtlMs ?? DEFAULT_KEY_TTL_MS;
    this.#discoveryTtlMs = options?.discoveryTtlMs ?? DEFAULT_DISCOVERY_TTL_MS;
    this.#fetchTimeoutMs = options?.fetchTimeoutMs ?? DEFAULT_FETCH_TIMEOUT_MS;
    this.#keyCacheMaxEntries =
      options?.keyCacheMaxEntries ?? DEFAULT_KEY_CACHE_MAX_ENTRIES;
    this.#jwksRefetchCooldownMs =
      options?.jwksRefetchCooldownMs ?? DEFAULT_JWKS_REFETCH_COOLDOWN_MS;
  }

  async key(issuer: string, kid: string): Promise<CryptoKey> {
    const started = this.#generation;
    const cacheKey = keyCacheKey(issuer, kid);
    const cached = this.#getCached(this.#keyCache, cacheKey);
    if (cached) {
      return cached;
    }

    const jwksUri = await this.#resolveJwksUri(issuer, started);
    return this.#resolveKey(issuer, kid, jwksUri, cacheKey, started);
  }

  invalidate(issuer: string, kid: string): void {
    this.#generation++;
    this.#clearInflight();
    const cacheKey = keyCacheKey(issuer, kid);
    this.#keyCache.delete(cacheKey);
    const jwksUri = this.#discoveryCache.get(issuer)?.value;
    if (jwksUri) {
      this.#jwksCache.delete(jwksUri);
      this.#jwksRetry.delete(jwksUri);
    }
    this.#discoveryCache.delete(issuer);
    this.#discoveryRetry.delete(issuer);
  }

  /**
   * Drops all cached keys, JWKS URI discoveries, and inflight resolutions.
   * Use after a global key rotation when targeted `invalidate(issuer, kid)`
   * is impractical. Subsequent `key()` calls re-discover and re-fetch.
   */
  clear(): void {
    this.#generation++;
    this.#clearInflight();
    this.#keyCache.clear();
    this.#jwksCache.clear();
    this.#discoveryCache.clear();
    this.#discoveryRetry.clear();
    this.#jwksRetry.clear();
  }

  #clearInflight(): void {
    this.#keyInflight.clear();
    this.#jwksInflight.clear();
    this.#discoveryInflight.clear();
  }

  // -------------------------------------------------------
  // Discovery resolution with cache + dedup
  // -------------------------------------------------------

  async #resolveJwksUri(issuer: string, started: number): Promise<string> {
    const cached = this.#getCached(this.#discoveryCache, issuer);
    if (cached) {
      return cached;
    }

    const inflight = this.#discoveryInflight.get(issuer);
    if (inflight) {
      return inflight;
    }

    this.#discoveryRetry.check(issuer, performance.now());
    const promise = (async () => {
      try {
        const metadata = await fetchAuthorizationServerMetadata(issuer, {
          signal: AbortSignal.timeout(this.#fetchTimeoutMs),
        }).catch((cause: unknown) => {
          const retryable = cause instanceof ResponseBodyTooLargeError
            ? cause.retryable
            : !(cause instanceof OAuthError) && isTransientMetadataFailure(cause);
          const detail = cause instanceof Error ? cause.message : String(cause);
          const error = new JWKSDiscoveryError(`Discovery failed for "${issuer}": ${detail}`, { retryable, cause });
          if (retryable && started === this.#generation) {
            this.#discoveryRetry.record(issuer, error, cause, performance.now());
          }
          throw error;
        });
        if (!metadata.jwks_uri) {
          throw new JWKSDiscoveryError(`No JSON Web Key Set available for "${issuer}"`);
        }

        assertSameOrigin(issuer, metadata.jwks_uri);

        if (started === this.#generation) {
          this.#discoveryCache.set(issuer, {
            value: metadata.jwks_uri,
            expiresAt: Date.now() + this.#discoveryTtlMs,
          });
          this.#discoveryRetry.delete(issuer);
        }

        return metadata.jwks_uri;
      } finally {
        if (started === this.#generation) this.#discoveryInflight.delete(issuer);
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
    started: number,
  ): Promise<CryptoKey> {
    const inflight = this.#keyInflight.get(cacheKey);
    if (inflight) {
      return inflight;
    }

    const promise = (async () => {
      try {
        let entry = this.#jwksCache.get(jwksUri);
        if (entry && Date.now() >= entry.expiresAt) {
          this.#jwksCache.delete(jwksUri);
          entry = undefined;
        }
        let jwk = entry?.value.keys.find((jwk) => jwk.kid === kid);
        if (!jwk && (!entry || Date.now() - entry.fetchedAt >= this.#jwksRefetchCooldownMs)) {
          const jwkSet = await this.#fetchJwks(issuer, jwksUri, started);
          jwk = jwkSet.keys.find((jwk) => jwk.kid === kid);
        }
        if (!jwk) {
          throw new JWKSKeyNotFoundError(`Failed to find key "${kid}" of "${issuer}"`);
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

        if (started === this.#generation) {
          this.#keyCache.set(cacheKey, {
            value: key,
            expiresAt: Date.now() + this.#keyTtlMs,
          });
          this.#evictKeysIfNeeded();
        }

        return key;
      } finally {
        if (started === this.#generation) this.#keyInflight.delete(cacheKey);
      }
    })();

    if (started === this.#generation) this.#keyInflight.set(cacheKey, promise);
    return promise;
  }

  // -------------------------------------------------------
  // JWKS fetch with dedup: concurrent misses for any kid share one fetch
  // -------------------------------------------------------

  async #fetchJwks(issuer: string, jwksUri: string, started: number): Promise<JWKSet> {
    const inflight = this.#jwksInflight.get(jwksUri);
    if (inflight) {
      return inflight;
    }

    this.#jwksRetry.check(jwksUri, performance.now());
    const promise = (async () => {
      try {
        const message = `Failed to fetch JWKS from "${jwksUri}" for "${issuer}"`;
        let text: string;
        try {
          const response = await fetch(jwksUri, { signal: AbortSignal.timeout(this.#fetchTimeoutMs) });
          if (!response.ok) {
            discardResponseBody(response);
            throw new HTTPError(`${message} (HTTP ${response.status})`, response.status, undefined,
              response.headers?.get("Retry-After") ?? undefined);
          }
          text = await readResponseText(response);
        } catch (cause) {
          const retryable = isTransientMetadataFailure(cause);
          const detail = cause instanceof ResponseBodyTooLargeError ? `${message}: ${cause.message}` : message;
          const error = new JWKSFetchError(cause instanceof HTTPError ? cause.message : detail, { retryable, cause });
          if (retryable && started === this.#generation) {
            this.#jwksRetry.record(jwksUri, error, cause, performance.now());
          }
          throw error;
        }

        let document: unknown;
        try {
          document = JSON.parse(text);
        } catch (cause) {
          throw new JWKSFetchError(message, { retryable: false, cause });
        }
        const parsed = JWKSetSchema.safeParse(document);
        if (!parsed.success) throw new JWKSFetchError(message, { retryable: false, cause: parsed.error });
        const jwkSet = parsed.data;
        const now = Date.now();
        if (started === this.#generation) {
          this.#jwksCache.set(jwksUri, {
            value: jwkSet,
            fetchedAt: now,
            expiresAt: now + this.#keyTtlMs,
          });
          this.#jwksRetry.delete(jwksUri);
        }
        return jwkSet;
      } finally {
        if (started === this.#generation) this.#jwksInflight.delete(jwksUri);
      }
    })();

    if (started === this.#generation) this.#jwksInflight.set(jwksUri, promise);
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

  // Bound the key cache: evict the oldest-inserted entries (Map preserves
  // insertion order) so a verifier serving many keys does not grow without
  // limit. Exact eviction order is an implementation detail.
  #evictKeysIfNeeded(): void {
    while (this.#keyCache.size > this.#keyCacheMaxEntries) {
      const oldest = this.#keyCache.keys().next().value;
      if (oldest === undefined) {
        break;
      }
      this.#keyCache.delete(oldest);
    }
  }
}
