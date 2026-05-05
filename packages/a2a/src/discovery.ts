import type { AgentCard } from "./types.js";
import { A2A_AGENT_CARD_PATH } from "./types.js";

const DEFAULT_CACHE_TTL_MS = 15 * 60 * 1000; // 15 minutes

interface CacheEntry {
  card: AgentCard;
  expiresAt: number;
}

/**
 * Fetches and caches agent cards from remote A2A services.
 *
 * Python equivalent: `keycardai.a2a.ServiceDiscovery`
 */
export class ServiceDiscovery {
  #cacheTtlMs: number;
  #cache = new Map<string, CacheEntry>();

  constructor(options?: { cacheTtlMs?: number }) {
    this.#cacheTtlMs = options?.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS;
  }

  /**
   * Fetch the agent card from the given service URL.
   * Validates that the card has a `name` field.
   */
  async discoverService(serviceUrl: string): Promise<AgentCard> {
    const cardUrl = buildAgentCardUrl(serviceUrl);
    const response = await fetch(cardUrl, {
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(10_000),
    });
    if (!response.ok) {
      throw new Error(
        `ServiceDiscovery: failed to fetch agent card from "${cardUrl}" (HTTP ${response.status})`,
      );
    }
    let card: unknown;
    try {
      card = await response.json();
    } catch {
      throw new Error(`ServiceDiscovery: agent card at "${cardUrl}" is not valid JSON`);
    }
    validateAgentCard(card, cardUrl);
    return card as AgentCard;
  }

  /**
   * Return a cached agent card, fetching if absent or expired.
   */
  async getServiceCard(
    serviceUrl: string,
    options?: { forceRefresh?: boolean },
  ): Promise<AgentCard> {
    const key = normalizeUrl(serviceUrl);
    const cached = this.#cache.get(key);
    if (!options?.forceRefresh && cached && Date.now() < cached.expiresAt) {
      return cached.card;
    }
    const card = await this.discoverService(serviceUrl);
    this.#cache.set(key, { card, expiresAt: Date.now() + this.#cacheTtlMs });
    return card;
  }

  clearCache(): void {
    this.#cache.clear();
  }

  getCacheStats(): { size: number; keys: string[] } {
    return { size: this.#cache.size, keys: Array.from(this.#cache.keys()) };
  }
}

function buildAgentCardUrl(serviceUrl: string): string {
  const base = serviceUrl.endsWith("/") ? serviceUrl.slice(0, -1) : serviceUrl;
  return `${base}${A2A_AGENT_CARD_PATH}`;
}

function normalizeUrl(url: string): string {
  return url.endsWith("/") ? url.slice(0, -1) : url;
}

function validateAgentCard(card: unknown, url: string): asserts card is AgentCard {
  if (!card || typeof card !== "object" || Array.isArray(card)) {
    throw new Error(`ServiceDiscovery: agent card at "${url}" is not a JSON object`);
  }
  const obj = card as Record<string, unknown>;
  if (typeof obj.name !== "string" || !obj.name) {
    throw new Error(
      `ServiceDiscovery: agent card at "${url}" is missing required field "name"`,
    );
  }
}
