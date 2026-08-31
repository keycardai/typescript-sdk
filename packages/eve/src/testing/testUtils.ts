import type {
  ClientCredentialsRequest,
  ImpersonateRequest,
  JWTClaims,
  TokenExchangeRequest,
  TokenResponse,
} from "@keycardai/oauth";
import type { ConnectionPrincipal } from "eve/connections";
import type { SessionAuthContext } from "eve/context";

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
 * for.
 *
 * Covers the three cases the contract requires from a testing seam: successful
 * acquisition, failure of one resource, and failure of every call.
 */
export function fakeZoneClient(options: FakeZoneClientOptions = {}): FakeZoneClient {
  const calls: ZoneCalls = { exchanges: [], impersonations: [], clientCredentials: [] };

  const issue = (kind: string, resource: string | undefined): TokenResponse => {
    if (options.fail) throw options.fail;
    const failure = resource ? options.failResources?.[resource] : undefined;
    if (failure) throw failure;
    return {
      accessToken: `${kind}-token-for-${resource ?? "unknown"}`,
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
export function expiredJwt(secondsAgo = 60): string {
  return unsignedJwt({ exp: Math.floor(Date.now() / 1000) - secondsAgo, sub: "user-1" });
}

/** A JWT that is valid for another `secondsAhead` seconds. */
export function validJwt(secondsAhead = 3600, claims: Record<string, unknown> = {}): string {
  return unsignedJwt({
    exp: Math.floor(Date.now() / 1000) + secondsAhead,
    sub: "user-1",
    ...claims,
  });
}

/** A request carrying a bearer token. */
export function bearerRequest(token: string, url = "https://agent.example.com/chat"): Request {
  return new Request(url, { headers: { authorization: `Bearer ${token}` } });
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

/** A user connection principal. */
export function userPrincipal(
  id = "user-1",
  issuer = "https://zone.example.com",
  attributes?: Readonly<Record<string, string | readonly string[]>>,
): ConnectionPrincipal {
  return { type: "user", id, issuer, ...(attributes ? { attributes } : {}) };
}

/** The app connection principal. */
export function appPrincipal(): ConnectionPrincipal {
  return { type: "app" };
}

/** A session auth context, as `keycardAuth` would return it. */
export function sessionAuthContext(
  overrides: Partial<SessionAuthContext> = {},
): SessionAuthContext {
  return {
    attributes: {},
    authenticator: "keycard",
    issuer: "https://zone.example.com",
    principalId: "user-1",
    principalType: "user",
    ...overrides,
  };
}

/** The connection metadata eve passes to every authorization callback. */
export function connectionContext(url = "https://mcp.example.com/mcp"): { url: string } {
  return { url };
}
