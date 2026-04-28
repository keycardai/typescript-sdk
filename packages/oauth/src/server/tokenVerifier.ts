import { JWTVerifier } from "../jwt/verifier.js";
import { JWKSOAuthKeyring, type OAuthKeyring } from "../keyring.js";
import type { JWTClaims } from "../jwt/signer.js";
import type { AccessToken } from "./accessToken.js";

const DEFAULT_ZONE_KEY = "__default__";
const DEFAULT_ALLOWED_ALGORITHMS = ["RS256"] as const;
// Sentinel: per-zone audience dict configured but zoneId has no entry.
// Verification fails closed rather than silently dropping audience validation.
const REQUIRED_AUDIENCE_MISSING = Symbol("required-audience-missing");

export interface TokenVerifierOptions {
  /**
   * Issuer URL for the Keycard zone, e.g. "https://zone-id.keycard.cloud" for
   * single-zone deployments. With `enableMultiZone: true`, this is the base
   * URL whose host gets prefixed with the per-request zoneId.
   */
  issuer: string;
  /**
   * Required scopes. When set, every value must be present in the token's
   * `scope` claim or verification returns null.
   */
  requiredScopes?: readonly string[];
  /**
   * Allowed signing algorithms. Defaults to ["RS256"].
   */
  allowedAlgorithms?: readonly string[];
  /**
   * When true, callers can supply a per-request zoneId via verifyTokenForZone.
   * Each zone gets its own issuer URL and audience.
   */
  enableMultiZone?: boolean;
  /**
   * Audience to validate against. A single string applies to every zone.
   * A `Record<zoneId, audience>` selects the audience per zone.
   */
  audience?: string | Record<string, string>;
  /**
   * Custom keyring (e.g. for testing or shared caches). When omitted,
   * a fresh JWKSOAuthKeyring is constructed.
   */
  keyring?: OAuthKeyring;
}

export class TokenVerifier {
  #issuer: string;
  #requiredScopes: readonly string[];
  #allowedAlgorithms: readonly string[];
  #enableMultiZone: boolean;
  #audience?: string | Record<string, string>;
  #keyring: OAuthKeyring;
  #verifiers: Map<string, JWTVerifier>;

  constructor(options: TokenVerifierOptions) {
    if (!options.issuer) {
      throw new Error("TokenVerifier: issuer is required");
    }
    this.#issuer = options.issuer;
    this.#requiredScopes = options.requiredScopes ?? [];
    this.#allowedAlgorithms = options.allowedAlgorithms ?? DEFAULT_ALLOWED_ALGORITHMS;
    this.#enableMultiZone = options.enableMultiZone ?? false;
    this.#audience = options.audience;
    this.#keyring = options.keyring ?? new JWKSOAuthKeyring();
    this.#verifiers = new Map();
  }

  async verifyToken(token: string): Promise<AccessToken | null> {
    return this.#verify(token, undefined);
  }

  async verifyTokenForZone(token: string, zoneId: string): Promise<AccessToken | null> {
    if (!zoneId) {
      return null;
    }
    return this.#verify(token, zoneId);
  }

  clearCache(): void {
    this.#verifiers.clear();
  }

  async #verify(token: string, zoneId: string | undefined): Promise<AccessToken | null> {
    try {
      const verifier = this.#getVerifier(zoneId);
      if (!verifier) {
        return null;
      }
      const claims = await verifier.verify(token);
      if (!this.#scopesSatisfied(claims)) {
        return null;
      }
      return this.#toAccessToken(token, claims);
    } catch {
      return null;
    }
  }

  #getVerifier(zoneId: string | undefined): JWTVerifier | null {
    const cacheKey = zoneId ?? DEFAULT_ZONE_KEY;
    const cached = this.#verifiers.get(cacheKey);
    if (cached) {
      return cached;
    }

    const audienceResult = this.#resolveAudience(zoneId);
    if (audienceResult === REQUIRED_AUDIENCE_MISSING) {
      return null;
    }

    const issuer = this.#enableMultiZone && zoneId
      ? buildZoneScopedIssuer(this.#issuer, zoneId)
      : this.#issuer;

    const verifier = new JWTVerifier(this.#keyring, {
      issuers: [issuer],
      audiences: audienceResult,
      algorithms: this.#allowedAlgorithms,
    });
    this.#verifiers.set(cacheKey, verifier);
    return verifier;
  }

  #resolveAudience(zoneId: string | undefined): string | undefined | typeof REQUIRED_AUDIENCE_MISSING {
    if (this.#audience === undefined) {
      return undefined;
    }
    if (typeof this.#audience === "string") {
      return this.#audience;
    }
    if (zoneId && Object.prototype.hasOwnProperty.call(this.#audience, zoneId)) {
      return this.#audience[zoneId];
    }
    return REQUIRED_AUDIENCE_MISSING;
  }

  #scopesSatisfied(claims: JWTClaims): boolean {
    if (this.#requiredScopes.length === 0) {
      return true;
    }
    if (typeof claims.scope !== "string") {
      return false;
    }
    const tokenScopes = new Set(claims.scope.split(" ").filter(Boolean));
    return this.#requiredScopes.every((s) => tokenScopes.has(s));
  }

  #toAccessToken(token: string, claims: JWTClaims): AccessToken {
    const scopes = typeof claims.scope === "string"
      ? claims.scope.split(" ").filter(Boolean)
      : [];
    const resourceClaim = claims["resource"];
    const resource = typeof resourceClaim === "string" ? resourceClaim : undefined;
    const expiresAt = typeof claims.exp === "number" ? claims.exp : undefined;
    return {
      token,
      clientId: typeof claims.client_id === "string" ? claims.client_id : "",
      scopes,
      expiresAt,
      resource,
    };
  }
}

function buildZoneScopedIssuer(baseIssuer: string, zoneId: string): string {
  const url = new URL(baseIssuer);
  return `${url.protocol}//${zoneId}.${url.host}`;
}
