import {
  JWKSOAuthKeyring,
  JWTVerifier,
  type JWTClaims,
  type OAuthKeyring,
} from "@keycardai/oauth";
import type { AuthFn } from "eve/channels/auth";
import type { SessionAuthContext } from "eve/context";

import { RouteRejectedError } from "./errors.js";
import { decodeClaims } from "./expiry.js";
import {
  defaultSubjectTokenStore,
  principalKey,
  SUBJECT_TOKEN_ATTRIBUTE,
  type SubjectTokenStore,
} from "./subjectTokens.js";

/** Claims never copied into `SessionAuthContext.attributes`. */
const RESERVED_CLAIMS = new Set([
  "aud",
  "exp",
  "iat",
  "iss",
  "jti",
  "nbf",
  "sub",
  SUBJECT_TOKEN_ATTRIBUTE,
]);

/**
 * How the verified inbound bearer is kept for a later on-behalf-of exchange.
 *
 * - `"memory"` (default): a process-local store keyed by the principal eve
 *   projects onto a connection. Nothing is written to durable session state.
 *   A turn that resumes in another process finds no token and fails closed.
 * - `"attributes"`: the token rides on `SessionAuthContext.attributes`, which
 *   eve persists with the session and copies onto the connection principal.
 *   Survives restarts and reaches connections in other processes, at the cost
 *   of a bearer token in durable state.
 * - `"none"`: nothing is retained. For zones where connections only ever run
 *   `asSelf` or `impersonate`.
 */
export type SubjectTokenRetention = "attributes" | "memory" | "none";

export interface KeycardAuthOptions {
  /** Keycard zone URL (issuer). Required unless `verify` is given. */
  zoneUrl?: string;
  /** Audience(s) the token must carry. Omit to skip audience validation. */
  audience?: string | readonly string[];
  /** `principalType` for the session context. Defaults to `"user"`. */
  principalType?: string;
  /** Scopes the token must carry. Missing scopes reject the request. */
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
  /** Extra attributes for the session context, from the verified claims. */
  attributes?: (
    claims: JWTClaims,
  ) => Readonly<Record<string, string | readonly string[]>>;
  /** Retention mode for the inbound bearer. Defaults to `"memory"`. */
  retainSubjectToken?: SubjectTokenRetention;
  /** Store for `"memory"` retention. Defaults to the shared store. */
  subjectTokens?: SubjectTokenStore;
}

/**
 * A Keycard `AuthFn` for a channel's `auth` array.
 *
 * Verifies a zone-issued bearer and projects its claims onto eve's
 * `SessionAuthContext`. Three outcomes, matching eve's ordered walk:
 *
 * - No bearer, or a bearer this zone did not issue: returns `null`, so a later
 *   entry in the array (a shared secret, a local dev bypass) still gets a turn.
 * - A bearer this zone issued that does not verify, is expired, or is for
 *   another audience: throws with a 401 `Response`, which stops the walk. A
 *   broken Keycard credential is a rejection, not an invitation to fall
 *   through to something weaker.
 * - A verified bearer: returns the session context, and retains the token for
 *   `onBehalfOf`.
 *
 * The verifier and its keyring are built once per `keycardAuth` call and cache
 * discovery and signing keys, so a request pays no discovery round trip.
 */
export function keycardAuth(options: KeycardAuthOptions): AuthFn<Request> {
  if (!options.zoneUrl && !options.verify) {
    throw new Error("keycardAuth requires zoneUrl or verify");
  }

  const issuer = options.zoneUrl;
  const principalType = options.principalType ?? "user";
  const retention = options.retainSubjectToken ?? "memory";
  const store = options.subjectTokens ?? defaultSubjectTokenStore;
  const verify = options.verify ?? jwksVerifier(options, issuer!);

  return async (request: Request): Promise<SessionAuthContext | null> => {
    const token = bearerToken(request);
    if (token === null) return null;
    if (!recognized(token, issuer)) return null;

    let claims: JWTClaims;
    try {
      claims = await verify(token);
    } catch (cause) {
      throw new RouteRejectedError({
        message: cause instanceof Error ? cause.message : "Invalid token",
        code: "invalid_token",
        error: "invalid_token",
      });
    }

    const missing = missingScopes(claims, options.requiredScopes);
    if (missing.length > 0) {
      throw new RouteRejectedError({
        message: `Token is missing required scope(s): ${missing.join(", ")}`,
        code: "insufficient_scope",
        error: "insufficient_scope",
      });
    }

    const principalId = String(claims.sub);
    const attributes: Record<string, string | readonly string[]> = {
      ...claimAttributes(claims),
      ...options.attributes?.(claims),
    };

    const context: SessionAuthContext = {
      attributes,
      authenticator: "keycard",
      principalId,
      principalType,
      ...(typeof claims.iss === "string" ? { issuer: claims.iss } : {}),
      subject: principalId,
    };

    if (retention === "attributes") {
      attributes[SUBJECT_TOKEN_ATTRIBUTE] = token;
    } else if (retention === "memory") {
      store.set(principalKey(context), token);
    }

    return context;
  };
}

/** The warm JWKS-backed verifier used when no `verify` seam is supplied. */
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
 * Whether this bearer is a caller the zone issued.
 *
 * A decode-only issuer peek, so an unrelated credential in the same header
 * (another provider's token, an opaque API key) falls through to the next
 * `AuthFn` instead of rejecting the request. Nothing is trusted from this
 * decode: the verifier re-checks the issuer against the same allowlist before
 * any key lookup.
 */
function recognized(token: string, issuer: string | undefined): boolean {
  if (issuer === undefined) return true;
  const claims = decodeClaims(token);
  if (claims === null) return false;
  return claims.iss === issuer;
}

function bearerToken(request: Request): string | null {
  const header = request.headers.get("authorization");
  if (!header) return null;
  const [scheme, ...rest] = header.trim().split(/\s+/);
  if (!scheme || scheme.toLowerCase() !== "bearer") return null;
  const token = rest.join("");
  return token || null;
}

function missingScopes(claims: JWTClaims, required: readonly string[] | undefined): string[] {
  if (!required || required.length === 0) return [];
  const granted = new Set(tokenScopes(claims));
  return required.filter((scope) => !granted.has(scope));
}

function tokenScopes(claims: JWTClaims): string[] {
  const scope: unknown = claims.scope;
  if (typeof scope === "string") return scope.split(" ").filter(Boolean);
  if (Array.isArray(scope)) {
    return scope.filter((entry): entry is string => typeof entry === "string");
  }
  return [];
}

/**
 * Claims projected onto the session context.
 *
 * String and string-list claims only, minus JWT plumbing: attributes are
 * durable session state and reach connection principals, so structured claims
 * are left to an explicit `attributes` mapper.
 */
function claimAttributes(claims: JWTClaims): Record<string, string | readonly string[]> {
  const attributes: Record<string, string | readonly string[]> = {};
  for (const [name, value] of Object.entries(claims)) {
    if (RESERVED_CLAIMS.has(name)) continue;
    if (typeof value === "string") {
      attributes[name] = value;
    } else if (
      Array.isArray(value) &&
      value.every((entry): entry is string => typeof entry === "string")
    ) {
      attributes[name] = value;
    }
  }
  return attributes;
}
