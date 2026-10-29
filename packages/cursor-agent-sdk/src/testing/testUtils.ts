import type { AuthContext, SessionInfo } from "@grok/agent-sdk";
import type {
  ClientCredentialsRequest,
  ImpersonateRequest,
  JWTClaims,
  TokenExchangeRequest,
  TokenResponse,
} from "@keycardai/oauth";

import type { ZoneClient } from "../zoneClient.js";

/** Every call a fake zone client saw, in order. */
export interface ZoneCalls {
  readonly exchanges: TokenExchangeRequest[];
  readonly impersonations: ImpersonateRequest[];
  readonly clientCredentials: ClientCredentialsRequest[];
}

export interface FakeZoneClientOptions {
  /** Fails only these resources, leaving the rest to succeed. */
  failResources?: Readonly<Record<string, Error>>;
  /** Fails every call, whatever the resource. */
  fail?: Error;
  /** Advisory lifetime on issued tokens, in seconds. */
  expiresIn?: number;
}

/** A fake zone client with recorded calls and no network. */
export interface FakeZoneClient extends ZoneClient {
  readonly calls: ZoneCalls;
}

/**
 * A zone client that mints deterministic tokens and records what it was asked
 * for. Each call mints a distinct token, so a test can tell a cache hit from
 * a fresh grant.
 */
export function fakeZoneClient(options: FakeZoneClientOptions = {}): FakeZoneClient {
  const calls: ZoneCalls = { exchanges: [], impersonations: [], clientCredentials: [] };
  let serial = 0;

  const issue = (kind: string, resource: string | undefined): TokenResponse => {
    if (options.fail) throw options.fail;
    const failure = resource ? options.failResources?.[resource] : undefined;
    if (failure) throw failure;
    serial += 1;
    return {
      accessToken: `${kind}-token-${serial}-for-${resource ?? "unknown"}`,
      tokenType: "Bearer",
      ...(options.expiresIn !== undefined ? { expiresIn: options.expiresIn } : {}),
    };
  };

  return {
    calls,
    async exchangeToken(request) {
      calls.exchanges.push(request);
      return issue("exchanged", request.resource);
    },
    async impersonate(request) {
      calls.impersonations.push(request);
      return issue("impersonated", request.resource);
    },
    async clientCredentialsGrant(request) {
      calls.clientCredentials.push(request ?? {});
      return issue("app", request?.resource);
    },
  };
}

/** An unsigned JWT with the given claims, for decode-only paths. */
export function unsignedJwt(claims: Record<string, unknown>): string {
  const encode = (value: unknown): string =>
    Buffer.from(JSON.stringify(value)).toString("base64url");
  return `${encode({ alg: "RS256", typ: "JWT" })}.${encode(claims)}.signature`;
}

/** A JWT that expired `secondsAgo` seconds ago. */
export function expiredJwt(secondsAgo = 60, claims: Record<string, unknown> = {}): string {
  return unsignedJwt({ exp: Math.floor(Date.now() / 1000) - secondsAgo, sub: "user-1", ...claims });
}

/** A JWT that is valid for another `secondsAhead` seconds. */
export function validJwt(secondsAhead = 3600, claims: Record<string, unknown> = {}): string {
  return unsignedJwt({
    exp: Math.floor(Date.now() / 1000) + secondsAhead,
    sub: "user-1",
    ...claims,
  });
}

/** A verification seam that accepts one token and rejects everything else. */
export function fakeVerifier(
  accepted: string,
  claims: JWTClaims,
): (token: string) => Promise<JWTClaims> {
  return async (token: string) => {
    if (token !== accepted) throw new Error("Invalid token");
    return claims;
  };
}

/** The `AuthContext` `keycardAuth` returns for a zone user. */
export function keycardPrincipal(
  overrides: Partial<AuthContext> = {},
  issuer = "https://zone.example.com",
): AuthContext {
  return {
    authenticator: "keycard",
    principalId: "user-1",
    principalType: "user",
    attributes: { iss: issuer },
    ...overrides,
  };
}

/** A `SessionInfo` carrying the given principal, as a connection `auth` callback receives it. */
export function session(auth: AuthContext | null, overrides: Partial<SessionInfo> = {}): SessionInfo {
  return {
    id: "session-1",
    channelId: "http",
    mode: "chat",
    auth,
    ...overrides,
  } as SessionInfo;
}
