/**
 * The default verification path of `zoneAuthenticator`.
 *
 * The seam-injected tests cover everything after verification; these cover the
 * verification the SDK does when no seam is passed, with `@keycardai/oauth`
 * mocked so the suite reaches no zone and no JWKS endpoint.
 */

import { beforeEach, describe, expect, it, jest } from "@jest/globals";

interface VerifierOptions {
  issuers: string[];
  audiences: string[];
}

const built: VerifierOptions[] = [];
const claims: { current: Record<string, unknown> } = { current: {} };
const verified: string[] = [];

jest.unstable_mockModule("@keycardai/oauth", () => ({
  JWKSOAuthKeyring: class {},
  JWTVerifier: class {
    constructor(_keyring: unknown, options: VerifierOptions) {
      built.push(options);
    }
    async verify(token: string): Promise<Record<string, unknown>> {
      verified.push(token);
      if (token !== "token-a") throw new Error("signature does not verify");
      return claims.current;
    }
  },
}));

const { zoneAuthenticator } = await import("./servedAuth.js");

const ZONE = "https://zone.example.test";
const RESOURCE = "https://agent.example.test";
const ADA = "ada@example.test";

function request(authorization: string): Request {
  return new Request("https://agent.example.test/threads", {
    method: "POST",
    headers: { authorization },
  });
}

beforeEach(() => {
  built.length = 0;
  verified.length = 0;
  claims.current = {};
});

describe("zoneAuthenticator default verification", () => {
  it("verifies against the zone at this agent's resource", async () => {
    claims.current = { email: ADA, sub: "abc", scope: "openid email" };
    const hook = zoneAuthenticator({ zoneUrl: ZONE, resource: RESOURCE });
    // Nothing is built until a request arrives, so importing an auth module
    // never reaches the zone.
    expect(built).toEqual([]);
    const user = await hook(request("Bearer token-a"));
    expect(built).toEqual([{ issuers: [ZONE], audiences: [RESOURCE] }]);
    expect(user.identity).toBe(ADA);
    expect(user.permissions).toEqual(["openid", "email"]);
    expect(user.subject_token).toBe("token-a");
  });

  it("strips a trailing slash off the configured zone URL", async () => {
    // Zone tokens carry no trailing slash in their issuer and the verifier
    // matches issuers exactly, so a configured slash would reject every token.
    claims.current = { email: ADA };
    const hook = zoneAuthenticator({ zoneUrl: `${ZONE}/`, resource: RESOURCE });
    await hook(request("Bearer token-a"));
    expect(built).toEqual([{ issuers: [ZONE], audiences: [RESOURCE] }]);
  });

  it("builds the verifier once and reuses it", async () => {
    claims.current = { email: ADA };
    const hook = zoneAuthenticator({ zoneUrl: ZONE, resource: RESOURCE });
    await hook(request("Bearer token-a"));
    await hook(request("Bearer token-a"));
    expect(built).toHaveLength(1);
    expect(verified).toEqual(["token-a", "token-a"]);
  });

  it("falls back to the subject claim when the token carries no email", async () => {
    claims.current = { sub: "user-abc" };
    const hook = zoneAuthenticator({ zoneUrl: ZONE, resource: RESOURCE });
    const user = await hook(request("Bearer token-a"));
    expect(user.identity).toBe("user-abc");
    expect(user.permissions).toEqual([]);
  });

  it("challenges a token with no usable identity claim", async () => {
    claims.current = { iss: ZONE };
    const hook = zoneAuthenticator({ zoneUrl: ZONE, resource: RESOURCE });
    await expect(hook(request("Bearer token-a"))).rejects.toMatchObject({
      status: 401,
    });
  });

  it("challenges a token the zone rejects", async () => {
    const hook = zoneAuthenticator({ zoneUrl: ZONE, resource: RESOURCE });
    await expect(hook(request("Bearer token-forged"))).rejects.toMatchObject({
      status: 401,
    });
  });
});
