import { OAuthKeyring } from "../keyring.js";
import { InvalidTokenError } from "../errors.js";
import base64url from "../base64url.js";
import type { JWTClaims } from "./signer.js";

export interface JWTVerifierOptions {
  /**
   * Issuer(s) this verifier will accept. The `iss` claim in a presented token
   * must exactly match (string equality) one of these values. Tokens with any
   * other issuer are rejected before any key lookup or network I/O runs.
   */
  issuers: string | readonly string[];

  /**
   * Audience(s) the token must be intended for. When configured, the token's
   * `aud` claim must be present and contain at least one of these values.
   * When omitted, audience is not validated.
   */
  audiences?: string | readonly string[];

  /**
   * Allowed JWT algorithms. Defaults to `["RS256"]`. The `alg` header of a
   * presented token must be a member. `"none"` is always rejected.
   */
  algorithms?: readonly string[];

  /**
   * Allowed clock skew for `exp` / `nbf` checks, in seconds. Default: 0.
   */
  clockSkewSec?: number;
}

const DEFAULT_ALGORITHMS = ["RS256"] as const;

export class JWTVerifier {
  #keyring: OAuthKeyring;
  #issuers: ReadonlySet<string>;
  #audiences?: ReadonlySet<string>;
  #algorithms: ReadonlySet<string>;
  #clockSkewSec: number;

  constructor(keyring: OAuthKeyring, options: JWTVerifierOptions) {
    const rawIssuers =
      typeof options?.issuers === "string" ? [options.issuers] : options?.issuers ?? [];
    if (rawIssuers.length === 0) {
      throw new Error("JWTVerifier requires at least one trusted issuer");
    }

    this.#keyring = keyring;
    this.#issuers = new Set(rawIssuers);
    this.#audiences = options.audiences
      ? new Set(
          typeof options.audiences === "string" ? [options.audiences] : options.audiences,
        )
      : undefined;
    this.#algorithms = new Set(options.algorithms ?? DEFAULT_ALGORITHMS);
    this.#clockSkewSec = options.clockSkewSec ?? 0;
  }

  async verify(token: string): Promise<JWTClaims> {
    const parts = token.split(".");
    if (parts.length !== 3) {
      throw new InvalidTokenError("Malformed JWT");
    }
    const [header, payload, signature] = parts;

    let jsonHeader: { alg?: string; kid?: string };
    let jsonPayload: JWTClaims;
    try {
      jsonHeader = JSON.parse(autob(header));
      jsonPayload = JSON.parse(autob(payload));
    } catch {
      throw new InvalidTokenError("Malformed JWT");
    }

    // Algorithm allowlist. Reject "none" and anything outside the allowlist
    // before any other work.
    if (!jsonHeader.alg || jsonHeader.alg === "none" || !this.#algorithms.has(jsonHeader.alg)) {
      throw new InvalidTokenError(`Unsupported JWT algorithm: ${jsonHeader.alg ?? "none"}`);
    }

    // Issuer allowlist. Rejected BEFORE any keyring call — guarantees a token
    // with an attacker-controlled `iss` can't trigger discovery against an
    // untrusted URL.
    if (!jsonPayload.iss) {
      throw new InvalidTokenError("JWT missing issuer (iss) claim");
    }
    if (!this.#issuers.has(jsonPayload.iss)) {
      throw new InvalidTokenError("Untrusted issuer");
    }

    // Required claims per RFC 9068 § 2.2.
    if (typeof jsonPayload.exp !== "number") {
      throw new InvalidTokenError("JWT missing expiration (exp) claim");
    }
    if (!jsonPayload.client_id) {
      throw new InvalidTokenError("JWT missing client_id claim");
    }

    // Time-based claims.
    const now = Math.floor(Date.now() / 1000);
    if (now > jsonPayload.exp + this.#clockSkewSec) {
      throw new InvalidTokenError("Token expired");
    }
    if (typeof jsonPayload.nbf === "number" && now + this.#clockSkewSec < jsonPayload.nbf) {
      throw new InvalidTokenError("Token not yet valid");
    }

    // Audience check, if configured. Missing `aud` fails closed when audiences
    // are required — matches RFC 8707 resource-indicator expectations.
    if (this.#audiences) {
      const aud = jsonPayload.aud;
      if (aud === undefined) {
        throw new InvalidTokenError("JWT missing audience (aud) claim");
      }
      const audValues = Array.isArray(aud) ? aud : [aud];
      const matched = audValues.some((a) => this.#audiences!.has(a));
      if (!matched) {
        throw new InvalidTokenError("Audience mismatch");
      }
    }

    // Only after all cheap policy checks do we touch the keyring.
    if (!jsonHeader.kid) {
      throw new InvalidTokenError("JWT missing key id (kid) header");
    }
    const key = await this.#keyring.key(jsonPayload.iss, jsonHeader.kid);

    const verified = await crypto.subtle.verify(
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: { name: "SHA-256" },
      },
      key,
      base64url.decode(signature),
      new TextEncoder().encode(`${header}.${payload}`),
    );
    if (!verified) {
      throw new InvalidTokenError("Invalid signature");
    }

    return jsonPayload;
  }
}

function autob(data: string): string {
  return atob(data.replace(/-/g, "+").replace(/_/g, "/"));
}
