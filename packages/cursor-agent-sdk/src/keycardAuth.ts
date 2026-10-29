import type { AuthContext } from "@grok/agent-sdk";
import {
  JWKSOAuthKeyring,
  JWTVerifier,
  type JWTClaims,
  type OAuthKeyring,
} from "@keycardai/oauth";

import { decodeClaims } from "./expiry.js";
import {
  defaultSubjectTokenStore,
  principalKey,
  SUBJECT_TOKEN_ATTRIBUTE,
  type SubjectTokenStore,
} from "./subjectTokens.js";

/** Claims never copied into `AuthContext.attributes`. `iss` is projected on purpose. */
const RESERVED_CLAIMS = new Set(["aud", "exp", "iat", "jti", "nbf", "sub", SUBJECT_TOKEN_ATTRIBUTE]);

/** The `authenticator` every `AuthContext` this verifier returns carries. */
export const KEYCARD_AUTHENTICATOR = "keycard";

/**
 * How the verified inbound bearer is kept for a later on-behalf-of exchange.
 *
 * - `"memory"` (default): a process-local store keyed by the principal.
 *   Nothing is written to the session record. A turn that runs in another
 *   process finds no token and fails closed.
 * - `"attributes"`: the token rides on `AuthContext.attributes`, which the SDK
 *   persists in `SessionRecord.auth`. Survives restarts and reaches turns in
 *   other processes, at the cost of a bearer token at rest.
 * - `"none"`: nothing is retained. For agents whose connections only run
 *   `asSelf` or `impersonate`.
 */
export type SubjectTokenRetention = "attributes" | "memory" | "none";

export interface KeycardAuthOptions {
  /** Keycard zone URL (issuer). Required unless `verify` is given. */
  zoneUrl?: string;
  /** Audience(s) the token must carry. Omit to skip audience validation. */
  audience?: string | readonly string[];
  /** `principalType` for the returned context. Defaults to `"user"`. */
  principalType?: "user" | "service";
  /** Scopes the token must carry. A missing scope returns null so the chain continues. */
  requiredScopes?: readonly string[];
  /** JWT algorithms to accept. Defaults to the verifier's own default. */
  algorithms?: readonly string[];
  /** Keyring for signing keys. Defaults to a cached JWKS keyring. */
  keyring?: OAuthKeyring;
  /**
   * Verification seam. Returns the verified claims, or throws to reject.
   * Replaces the JWKS-backed verifier, so tests take no network.
   */
  verify?: (token: string) => Promise<JWTClaims>;
  /** Extra attributes for the context, from the verified claims. Merged over the projected claims. */
  attributes?: (claims: JWTClaims) => Readonly<Record<string, string>>;
  /** Retention mode for the inbound bearer. Defaults to `"memory"`. */
  retainSubjectToken?: SubjectTokenRetention;
  /** Store for `"memory"` retention. Defaults to the shared store. */
  subjectTokens?: SubjectTokenStore;
}

/** The verifier shape `bearerAuth(verify)` accepts. */
export type KeycardTokenVerifier = (token: string) => Promise<AuthContext | null>;

/**
 * A Keycard token verifier for the channel's `bearerAuth` policy.
 *
 * Verifies a zone-issued bearer and returns the SDK's `AuthContext` for the
 * caller. `bearerAuth`'s verifier can only admit (an `AuthContext`) or pass
 * (null), so every other outcome is null and the chain continues: a bearer
 * this zone did not issue, a zone token that does not verify, and a token
 * missing a required scope. A deployment that must refuse such a request
 * places no admitting policy after this one.
 *
 * The verifier and its keyring are built once per `keycardAuth` call and cache
 * discovery and signing keys, so a request pays no discovery round trip.
 */
export function keycardAuth(options: KeycardAuthOptions): KeycardTokenVerifier {
  if (!options.zoneUrl && !options.verify) {
    throw new Error("keycardAuth requires zoneUrl or verify");
  }
  const principalType = options.principalType ?? "user";
  if (principalType !== "user" && principalType !== "service") {
    throw new Error('keycardAuth principalType must be "user" or "service"');
  }

  // Zone tokens carry no trailing slash in `iss`; a slash on the configured
  // zoneUrl would otherwise make every zone token unrecognized.
  const issuer = options.zoneUrl?.replace(/\/+$/, "");
  const retention = options.retainSubjectToken ?? "memory";
  const store = options.subjectTokens ?? defaultSubjectTokenStore;
  const verify = options.verify ?? jwksVerifier(options, issuer!);

  return async (token: string): Promise<AuthContext | null> => {
    if (!token || !recognized(token, issuer)) return null;

    let claims: JWTClaims;
    try {
      claims = await verify(token);
    } catch {
      return null;
    }
    if (typeof claims.sub !== "string" || !claims.sub) return null;
    if (missingScopes(claims, options.requiredScopes).length > 0) return null;

    let extra: Readonly<Record<string, string>> = {};
    if (options.attributes) {
      try {
        extra = options.attributes(claims);
      } catch {
        // The verifier never throws into the policy chain.
        return null;
      }
    }
    const attributes: Record<string, string> = { ...claimAttributes(claims), ...extra };
    delete attributes[SUBJECT_TOKEN_ATTRIBUTE];
    // `iss` keys the subject-token store and the connections' zone check, so it
    // always comes from the verified claims, never from the attributes callback.
    if (typeof claims.iss === "string") {
      attributes.iss = claims.iss;
    } else {
      delete attributes.iss;
    }

    const context: AuthContext = {
      authenticator: KEYCARD_AUTHENTICATOR,
      principalId: claims.sub,
      principalType,
      attributes,
    };

    if (retention === "attributes") {
      attributes[SUBJECT_TOKEN_ATTRIBUTE] = token;
    } else if (retention === "memory") {
      store.set(principalKey(context), token);
    }

    return context;
  };
}

function jwksVerifier(
  options: KeycardAuthOptions,
  issuer: string,
): (token: string) => Promise<JWTClaims> {
  const verifier = new JWTVerifier(options.keyring ?? new JWKSOAuthKeyring(), {
    issuers: issuer,
    ...(options.audience ? { audiences: options.audience } : {}),
    ...(options.algorithms ? { algorithms: options.algorithms } : {}),
  });
  return (token) => verifier.verify(token);
}

/**
 * Whether this bearer is a caller the zone issued: a decode-only issuer peek,
 * so another provider's token falls through to the next policy instead of
 * being rejected here. Nothing is trusted from this decode.
 */
function recognized(token: string, issuer: string | undefined): boolean {
  if (issuer === undefined) return true;
  const claims = decodeClaims(token);
  if (claims === null) return false;
  return claims.iss === issuer;
}

function missingScopes(claims: JWTClaims, required: readonly string[] | undefined): string[] {
  if (!required || required.length === 0) return [];
  const granted = new Set(parseScopes(claims.scope));
  return required.filter((scope) => !granted.has(scope));
}

/** Scopes carried by a `scope` value, as a space-delimited string (RFC 6749) or a list. */
export function parseScopes(scope: unknown): string[] {
  if (typeof scope === "string") return scope.split(" ").filter(Boolean);
  if (Array.isArray(scope)) {
    return scope.filter((entry): entry is string => typeof entry === "string");
  }
  return [];
}

/**
 * Claims projected onto `AuthContext.attributes`, which is a string map:
 * string claims as they are, string-list claims space-joined, and nothing
 * structured. `iss` is kept so the connection factories can bind a principal
 * to the zone that issued it.
 */
function claimAttributes(claims: JWTClaims): Record<string, string> {
  const attributes: Record<string, string> = {};
  for (const [name, value] of Object.entries(claims)) {
    if (RESERVED_CLAIMS.has(name)) continue;
    if (typeof value === "string") {
      attributes[name] = value;
    } else if (
      Array.isArray(value) &&
      value.every((entry): entry is string => typeof entry === "string")
    ) {
      attributes[name] = value.join(" ");
    }
  }
  return attributes;
}
