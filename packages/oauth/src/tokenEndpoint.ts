import { fetchAuthorizationServerMetadata } from "./discovery.js";
import { HTTPError, OAuthError, TokenEndpointDiscoveryError } from "./errors.js";

export const DEFAULT_DISCOVERY_TTL_MS = 60 * 60 * 1000;
export const DEFAULT_NEGATIVE_TTL_MS = 60 * 1000;
const DEFAULT_FETCH_TIMEOUT_MS = 10_000;

export interface TokenEndpointCacheOptions {
  /** Cache lifetime for the discovered token endpoint. Default: 1 hour. */
  discoveryTtlMs?: number;
  /**
   * Longest a deterministic discovery failure (4xx other than 429, issuer
   * mismatch, malformed metadata, missing `token_endpoint`) is remembered.
   * Never exceeds `discoveryTtlMs`; 0 disables negative caching. Default: 1 minute.
   */
  negativeTtlMs?: number;
}

type CacheEntry =
  | { endpoint: string; error?: undefined; expiresAt: number }
  | { endpoint?: undefined; error: TokenEndpointDiscoveryError; expiresAt: number };

/**
 * Resolves and caches an issuer's token endpoint per the base rule that
 * metadata failures are not sticky: success is cached for `discoveryTtlMs`,
 * a transient failure caches nothing, a deterministic failure is remembered
 * for at most `negativeTtlMs`. Concurrent cold-cache callers share one
 * in-flight discovery, which is bounded by an internal timeout rather than
 * any caller's signal so no single caller can poison it for the others.
 */
export class TokenEndpointResolver {
  #issuer: string;
  #discoveryTtlMs: number;
  #negativeTtlMs: number;
  #fetchTimeoutMs: number;
  #cached?: CacheEntry;
  #inflight?: Promise<string>;

  constructor(issuer: string, options?: TokenEndpointCacheOptions & { fetchTimeoutMs?: number }) {
    this.#issuer = issuer;
    this.#discoveryTtlMs = options?.discoveryTtlMs ?? DEFAULT_DISCOVERY_TTL_MS;
    this.#negativeTtlMs = options?.negativeTtlMs ?? DEFAULT_NEGATIVE_TTL_MS;
    this.#fetchTimeoutMs = options?.fetchTimeoutMs ?? DEFAULT_FETCH_TIMEOUT_MS;
  }

  async resolve(): Promise<string> {
    const cached = this.#cached;
    if (cached && Date.now() < cached.expiresAt) {
      if (cached.error) throw cached.error;
      return cached.endpoint;
    }

    if (this.#inflight) {
      return this.#inflight;
    }

    const promise = (async () => {
      try {
        return await this.#discover();
      } finally {
        this.#inflight = undefined;
      }
    })();
    this.#inflight = promise;
    return promise;
  }

  async #discover(): Promise<string> {
    let tokenEndpoint: string | undefined;
    try {
      const metadata = await fetchAuthorizationServerMetadata(this.#issuer, {
        signal: AbortSignal.timeout(this.#fetchTimeoutMs),
      });
      tokenEndpoint = metadata.token_endpoint;
    } catch (cause) {
      throw this.#store(
        new TokenEndpointDiscoveryError(
          `Failed to discover token endpoint for "${this.#issuer}": ${describe(cause)}`,
          { retryable: !isDeterministicDiscoveryFailure(cause), cause },
        ),
      );
    }

    if (!tokenEndpoint) {
      throw this.#store(
        new TokenEndpointDiscoveryError(
          `Authorization server "${this.#issuer}" does not advertise a token_endpoint`,
          { retryable: false },
        ),
      );
    }

    this.#cached = { endpoint: tokenEndpoint, expiresAt: Date.now() + this.#discoveryTtlMs };
    return tokenEndpoint;
  }

  #store(error: TokenEndpointDiscoveryError): TokenEndpointDiscoveryError {
    if (!error.retryable && this.#negativeTtlMs > 0) {
      const ttl = Math.min(this.#negativeTtlMs, this.#discoveryTtlMs);
      this.#cached = { error, expiresAt: Date.now() + ttl };
    }
    return error;
  }
}

/** Transport errors, timeouts, 5xx and 429 are transient; everything the metadata document itself gets wrong is deterministic. */
function isDeterministicDiscoveryFailure(cause: unknown): boolean {
  if (cause instanceof HTTPError) {
    return cause.status !== undefined && cause.status >= 400 && cause.status < 500 && cause.status !== 429;
  }
  return cause instanceof OAuthError;
}

function describe(cause: unknown): string {
  return cause instanceof Error ? cause.message : String(cause);
}
