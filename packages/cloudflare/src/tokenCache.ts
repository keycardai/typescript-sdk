import { TokenExchangeClient } from "@keycardai/oauth/tokenExchange";
import type { TokenResponse } from "@keycardai/oauth/tokenExchange";
import type { ApplicationCredential } from "./credentials.js";

export interface IsolateSafeTokenCacheOptions {
  /** Seconds to subtract from token expiry for safety margin. Default: 30. */
  skewSeconds?: number;
  /** Maximum cache entries to prevent unbounded memory in long-lived isolates. Default: 1000. */
  maxEntries?: number;
}

interface CacheEntry {
  response: TokenResponse;
  expiresAt: number;
}

/**
 * Per-user token cache that is safe for Cloudflare Workers isolate reuse.
 *
 * Cache key: `${jwt_sub}::${resource}` — ensures user A's upstream token
 * is never returned for user B, even when requests share the same isolate.
 */
export class IsolateSafeTokenCache {
  #client: TokenExchangeClient;
  #credential?: ApplicationCredential;
  #cache = new Map<string, CacheEntry>();
  #inflight = new Map<string, Promise<TokenResponse>>();
  #skewSeconds: number;
  #maxEntries: number;

  constructor(
    client: TokenExchangeClient,
    options?: IsolateSafeTokenCacheOptions & { credential?: ApplicationCredential },
  ) {
    this.#client = client;
    this.#credential = options?.credential;
    this.#skewSeconds = options?.skewSeconds ?? 30;
    this.#maxEntries = options?.maxEntries ?? 1000;
  }

  /**
   * Get an upstream access token, using the cache when possible.
   *
   * @param subject - JWT subject claim (user identity for cache keying)
   * @param subjectToken - The user's bearer token for token exchange
   * @param resource - The upstream resource URL to exchange for
   */
  async getToken(
    subject: string,
    subjectToken: string,
    resource: string,
  ): Promise<TokenResponse> {
    const cacheKey = `${subject}::${resource}`;
    const now = Date.now();

    // Check cache
    const cached = this.#cache.get(cacheKey);
    if (cached && cached.expiresAt > now) {
      return cached.response;
    }

    // Deduplicate concurrent requests for the same user+resource
    const inflight = this.#inflight.get(cacheKey);
    if (inflight) {
      return inflight;
    }

    const promise = this.#exchange(subjectToken, resource);
    this.#inflight.set(cacheKey, promise);

    try {
      const response = await promise;

      // Cache with TTL derived from expires_in
      const expiresInMs = (response.expiresIn ?? 3600) * 1000;
      const expiresAt = now + expiresInMs - this.#skewSeconds * 1000;

      this.#evictIfNeeded();
      this.#cache.set(cacheKey, { response, expiresAt });

      return response;
    } finally {
      this.#inflight.delete(cacheKey);
    }
  }

  async #exchange(subjectToken: string, resource: string): Promise<TokenResponse> {
    if (this.#credential) {
      const request = await this.#credential.prepareTokenExchangeRequest(subjectToken, resource);
      return this.#client.exchangeToken(request);
    }

    return this.#client.exchangeToken({
      subjectToken,
      resource,
      subjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
    });
  }

  #evictIfNeeded(): void {
    if (this.#cache.size < this.#maxEntries) return;

    // Evict expired entries first
    const now = Date.now();
    for (const [key, entry] of this.#cache) {
      if (entry.expiresAt <= now) {
        this.#cache.delete(key);
      }
    }

    // If still over limit, evict oldest entries
    if (this.#cache.size >= this.#maxEntries) {
      const keysToDelete = Array.from(this.#cache.keys()).slice(
        0,
        Math.ceil(this.#maxEntries / 4),
      );
      for (const key of keysToDelete) {
        this.#cache.delete(key);
      }
    }
  }
}
