import { afterEach, describe, expect, it, jest } from "@jest/globals";
import type { AuthContext } from "@grok/agent-sdk";
import {
  AuthProviderConfigurationError,
  type ApplicationCredential,
  type TokenExchangeRequest,
} from "@keycardai/oauth";
import { WorkloadIdentityConfigurationError } from "@keycardai/oauth/server";

import { asSelf, headersFor, impersonate, onBehalfOf } from "./connections.js";
import { WORKLOAD_IDENTITY_SOURCE_CURSOR_DEPLOYMENT } from "./cursorOidc.js";
import { ConnectionAuthError, FailureReason } from "./errors.js";
import { memorySubjectTokenStore, SUBJECT_TOKEN_ATTRIBUTE } from "./subjectTokens.js";
import {
  expiredJwt,
  fakeZoneClient,
  keycardPrincipal,
  session,
  unsignedJwt,
  validJwt,
} from "./testing/testUtils.js";

const ZONE = "https://zone.example.com";
const CALENDAR = "https://calendar.example.com";

function storeWith(token: string, principalId = "user-1") {
  const store = memorySubjectTokenStore();
  store.set(`${ZONE}|${principalId}`, token);
  return store;
}

async function failure(promise: Promise<unknown>): Promise<ConnectionAuthError> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(ConnectionAuthError);
    return error as ConnectionAuthError;
  }
  throw new Error("expected the provider to throw");
}

/** An assertion-based credential, as a workload or private-key credential is. */
class AssertionCredential implements ApplicationCredential {
  getAuth(): { clientId: string; clientSecret: string } | null {
    return null;
  }
  async prepareTokenExchangeRequest(
    subjectToken: string,
    resource: string,
  ): Promise<TokenExchangeRequest> {
    return {
      subjectToken,
      resource,
      subjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
      clientId: "app-1",
      clientAssertion: "assertion-jwt",
      clientAssertionType: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    } as TokenExchangeRequest;
  }
}

describe("impersonate", () => {
  it("row 1: exchanges for the Keycard principal and returns an authorization header", async () => {
    const client = fakeZoneClient();
    const auth = impersonate({ resource: CALENDAR, zoneUrl: ZONE, client });
    const result = await auth(session(keycardPrincipal()));
    expect(client.calls.impersonations).toEqual([{ userIdentifier: "user-1", resource: CALENDAR }]);
    expect(result.headers.authorization).toMatch(/^Bearer impersonated-token-1-for-/);
    expect(client.calls.exchanges).toHaveLength(0);
  });

  it("row 2: a callable userIdentifier receives any principal and bypasses the Keycard check", async () => {
    const client = fakeZoneClient();
    const seen: Array<AuthContext | null> = [];
    const auth = impersonate({
      resource: CALENDAR,
      zoneUrl: ZONE,
      client,
      userIdentifier: (ctx) => {
        seen.push(ctx);
        return "mapped-user";
      },
    });
    const slack = { authenticator: "slack", principalId: "U1", principalType: "user" as const };
    await auth(session(slack));
    expect(seen).toEqual([slack]);
    expect(client.calls.impersonations[0]?.userIdentifier).toBe("mapped-user");
  });

  it("row 5: fails principal_required for null, foreign, service and other-zone principals", async () => {
    const client = fakeZoneClient();
    const auth = impersonate({ resource: CALENDAR, zoneUrl: ZONE, client });
    const cases: Array<AuthContext | null> = [
      null,
      { authenticator: "local-dev", principalId: "dev", principalType: "user" },
      keycardPrincipal({ principalType: "service" }),
      keycardPrincipal({}, "https://other.example.com"),
    ];
    for (const auth_ of cases) {
      const error = await failure(auth(session(auth_)));
      expect(error.reason).toBe(FailureReason.PRINCIPAL_REQUIRED);
    }
    expect(client.calls.impersonations).toHaveLength(0);
    expect(client.calls.clientCredentials).toHaveLength(0);
  });

  it("empty userIdentifier fails principal_required", async () => {
    const client = fakeZoneClient();
    const auth = impersonate({ resource: CALENDAR, zoneUrl: ZONE, client, userIdentifier: () => "  " });
    const error = await failure(auth(session(keycardPrincipal())));
    expect(error.reason).toBe(FailureReason.PRINCIPAL_REQUIRED);
  });

  it("rows 6 and 9: one grant serves turns and sessions of the same principal, whatever the continuationKey", async () => {
    const client = fakeZoneClient({ expiresIn: 3600 });
    const auth = impersonate({ resource: CALENDAR, zoneUrl: ZONE, client });
    const a = await auth(session(keycardPrincipal(), { continuationKey: "k1" }));
    const b = await auth(session(keycardPrincipal(), { continuationKey: "k2" }));
    const c = await auth(session(keycardPrincipal(), { id: "session-2" }));
    expect(client.calls.impersonations).toHaveLength(1);
    expect(b.headers).toEqual(a.headers);
    expect(c.headers).toEqual(a.headers);
  });

  it("row 7: a token within the skew is replaced", async () => {
    const client = fakeZoneClient({ expiresIn: 30 });
    const auth = impersonate({ resource: CALENDAR, zoneUrl: ZONE, client, expirySkewSeconds: 60 });
    const a = await auth(session(keycardPrincipal()));
    const b = await auth(session(keycardPrincipal()));
    expect(client.calls.impersonations).toHaveLength(2);
    expect(b.headers.authorization).not.toEqual(a.headers.authorization);
  });

  it("row 8: two principals never share a token", async () => {
    const client = fakeZoneClient({ expiresIn: 3600 });
    const auth = impersonate({ resource: CALENDAR, zoneUrl: ZONE, client });
    const a = await auth(session(keycardPrincipal({ principalId: "user-1" })));
    const b = await auth(session(keycardPrincipal({ principalId: "user-2" })));
    expect(client.calls.impersonations).toHaveLength(2);
    expect(a.headers.authorization).not.toEqual(b.headers.authorization);
  });

  it("row 10: a zone refusal is acquisition_failed naming the code and resource, never a token", async () => {
    const client = fakeZoneClient({ fail: new Error("unauthorized_client") });
    const auth = impersonate({ resource: CALENDAR, zoneUrl: ZONE, client });
    const error = await failure(auth(session(keycardPrincipal())));
    expect(error.reason).toBe(FailureReason.ACQUISITION_FAILED);
    expect(error.message).toContain("unauthorized_client");
    expect(error.message).toContain(CALENDAR);
    expect(error.message).not.toContain("token-");

    const unknownUser = impersonate({ resource: CALENDAR, zoneUrl: ZONE, client: fakeZoneClient({ fail: new Error("invalid_grant") }) });
    const unknown = await failure(unknownUser(session(keycardPrincipal())));
    expect(unknown.reason).toBe(FailureReason.ACQUISITION_FAILED);
    expect(unknown.message).toContain("invalid_grant");
  });

  it("row 25: headerName changes the header", async () => {
    const auth = impersonate({ resource: CALENDAR, zoneUrl: ZONE, client: fakeZoneClient(), headerName: "x-api-key" });
    const result = await auth(session(keycardPrincipal()));
    expect(Object.keys(result.headers)).toEqual(["x-api-key"]);
    expect(result.headers["x-api-key"]).toMatch(/^Bearer /);
  });

  it("row 13: a string userIdentifier is a definition-time error", () => {
    expect(() =>
      impersonate({ resource: CALENDAR, zoneUrl: ZONE, userIdentifier: "fixed" as unknown as () => string }),
    ).toThrow(AuthProviderConfigurationError);
  });
});

describe("asSelf", () => {
  it("rows 3 and 4: client credentials with scopes, session.auth not read", async () => {
    const client = fakeZoneClient();
    const auth = asSelf({ resource: CALENDAR, zoneUrl: ZONE, client, requestScopes: ["a", "b"] });
    const trap = new Proxy({}, { get() { throw new Error("session.auth was read"); } });
    const result = await auth({ auth: trap as never } as never);
    expect(client.calls.clientCredentials).toEqual([{ resource: CALENDAR, scope: "a b" }]);
    expect(client.calls.exchanges).toHaveLength(0);
    expect(client.calls.impersonations).toHaveLength(0);
    expect(result.headers.authorization).toMatch(/^Bearer app-token-1-for-/);
  });

  it("row 10: invalid_target is acquisition_failed", async () => {
    const client = fakeZoneClient({ failResources: { [CALENDAR]: new Error("invalid_target") } });
    const error = await failure(asSelf({ resource: CALENDAR, zoneUrl: ZONE, client })(session(null)));
    expect(error.reason).toBe(FailureReason.ACQUISITION_FAILED);
    expect(error.message).toContain("invalid_target");
  });

  it("row 11: a SecretRef is read at call time, never at import", async () => {
    const name = "KEYCARD_TEST_SECRET_ROW11";
    delete process.env[name];
    const client = fakeZoneClient();
    const auth = asSelf({ resource: CALENDAR, zoneUrl: ZONE, client, clientId: "app-1", clientSecret: { secretName: name } });
    const error = await failure(auth(session(null)));
    expect(error.reason).toBe(FailureReason.CREDENTIAL_UNAVAILABLE);
    expect(error.message).toContain(name);
    expect(client.calls.clientCredentials).toHaveLength(0);
    process.env[name] = "s3cret";
    try {
      const result = await auth(session(null));
      expect(result.headers.authorization).toMatch(/^Bearer app-token-1-for-/);
      expect(JSON.stringify(client.calls)).not.toContain("s3cret");
    } finally {
      delete process.env[name];
    }
  });

  it("row 12: the shorthand builds a ClientSecret and sends no assertion", async () => {
    const client = fakeZoneClient();
    await asSelf({ resource: CALENDAR, zoneUrl: ZONE, client, clientId: "app-1", clientSecret: "s" })(session(null));
    expect(client.calls.clientCredentials[0]).toEqual({ resource: CALENDAR });
  });

  it("row 14: an assertion credential reaches the grant and the exchange", async () => {
    const client = fakeZoneClient();
    await asSelf({ resource: CALENDAR, zoneUrl: ZONE, client, applicationCredential: new AssertionCredential() })(session(null));
    expect(client.calls.clientCredentials[0]).toMatchObject({
      clientAssertion: "assertion-jwt",
      clientAssertionType: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      clientId: "app-1",
    });
    const store = storeWith(validJwt());
    await onBehalfOf({ resource: CALENDAR, zoneUrl: ZONE, client, applicationCredential: new AssertionCredential(), subjectTokens: store })(session(keycardPrincipal()));
    expect(client.calls.exchanges[0]).toMatchObject({ clientAssertion: "assertion-jwt" });
  });

  it("row 13: configuration errors at definition time", () => {
    expect(() => asSelf({ resource: CALENDAR, zoneUrl: ZONE, clientId: "a", clientSecret: "b", applicationCredential: new AssertionCredential() })).toThrow(AuthProviderConfigurationError);
    expect(() => asSelf({ resource: CALENDAR, zoneUrl: ZONE, clientId: "a" })).toThrow(AuthProviderConfigurationError);
    expect(() => asSelf({ resource: CALENDAR, zoneUrl: ZONE, clientSecret: "b" })).toThrow(AuthProviderConfigurationError);
    expect(() => asSelf({ resource: " ", zoneUrl: ZONE })).toThrow(AuthProviderConfigurationError);
    expect(() => asSelf({ resource: CALENDAR })).toThrow(AuthProviderConfigurationError);
  });
});

describe("onBehalfOf", () => {
  it("row 27: exchanges the retained token once and returns it", async () => {
    const client = fakeZoneClient({ expiresIn: 3600 });
    const token = validJwt();
    const auth = onBehalfOf({ resource: CALENDAR, zoneUrl: ZONE, client, subjectTokens: storeWith(token), requestScopes: "calendar.read" });
    const a = await auth(session(keycardPrincipal()));
    await auth(session(keycardPrincipal()));
    expect(client.calls.exchanges).toEqual([
      expect.objectContaining({ subjectToken: token, resource: CALENDAR, scope: "calendar.read" }),
    ]);
    expect(a.headers.authorization).toMatch(/^Bearer exchanged-token-1-for-/);
  });

  it("rows 28 and 34: empty store and non-Keycard principals fail closed", async () => {
    const client = fakeZoneClient();
    const auth = onBehalfOf({ resource: CALENDAR, zoneUrl: ZONE, client, subjectTokens: memorySubjectTokenStore() });
    expect((await failure(auth(session(keycardPrincipal())))).reason).toBe(FailureReason.SUBJECT_TOKEN_UNAVAILABLE);
    expect((await failure(auth(session(null)))).reason).toBe(FailureReason.PRINCIPAL_REQUIRED);
    expect((await failure(auth(session({ authenticator: "local-dev", principalId: "u", principalType: "user" })))).reason).toBe(FailureReason.PRINCIPAL_REQUIRED);
    expect(client.calls.exchanges).toHaveLength(0);
    expect(client.calls.clientCredentials).toHaveLength(0);
  });

  it("row 34: a session with no Keycard principal fails before the store is read", async () => {
    const reads: string[] = [];
    const store = memorySubjectTokenStore();
    const spy = { ...store, get: (key: string) => { reads.push(key); return store.get(key); } };
    const auth = onBehalfOf({ resource: CALENDAR, zoneUrl: ZONE, client: fakeZoneClient(), subjectTokens: spy });
    expect((await failure(auth(session(null)))).reason).toBe(FailureReason.PRINCIPAL_REQUIRED);
    expect((await failure(auth(session({ authenticator: "local-dev", principalId: "u", principalType: "user" })))).reason).toBe(FailureReason.PRINCIPAL_REQUIRED);
    expect(reads).toEqual([]);
  });

  it("rows 29 and 30: an expired JWT is not sent; opaque tokens proceed", async () => {
    const client = fakeZoneClient();
    const expired = onBehalfOf({ resource: CALENDAR, zoneUrl: ZONE, client, subjectTokens: storeWith(expiredJwt()) });
    expect((await failure(expired(session(keycardPrincipal())))).reason).toBe(FailureReason.SUBJECT_TOKEN_EXPIRED);
    expect(client.calls.exchanges).toHaveLength(0);
    const opaque = onBehalfOf({ resource: CALENDAR, zoneUrl: ZONE, client, subjectTokens: storeWith("opaque-token") });
    await opaque(session(keycardPrincipal()));
    const noExp = onBehalfOf({ resource: CALENDAR, zoneUrl: ZONE, client, subjectTokens: storeWith(unsignedJwt({ sub: "user-1" })) });
    await noExp(session(keycardPrincipal()));
    expect(client.calls.exchanges.map((e) => e.subjectToken)).toEqual(["opaque-token", unsignedJwt({ sub: "user-1" })]);
  });

  it("row 31: each principal exchanges its own token", async () => {
    const client = fakeZoneClient({ expiresIn: 3600 });
    const store = memorySubjectTokenStore();
    const t1 = validJwt(3600, { sub: "user-1" });
    const t2 = validJwt(3600, { sub: "user-2" });
    store.set(`${ZONE}|user-1`, t1);
    store.set(`${ZONE}|user-2`, t2);
    const auth = onBehalfOf({ resource: CALENDAR, zoneUrl: ZONE, client, subjectTokens: store });
    const a = await auth(session(keycardPrincipal({ principalId: "user-1" })));
    const b = await auth(session(keycardPrincipal({ principalId: "user-2" })));
    expect(client.calls.exchanges.map((e) => e.subjectToken)).toEqual([t1, t2]);
    expect(a.headers.authorization).not.toEqual(b.headers.authorization);
  });

  it("row 32: the memory store prunes expired tokens on the next write", async () => {
    const store = memorySubjectTokenStore();
    store.set(`${ZONE}|user-1`, expiredJwt());
    store.set(`${ZONE}|user-2`, validJwt(3600, { sub: "user-2" }));
    expect(store.get(`${ZONE}|user-1`)).toBeUndefined();
    const auth = onBehalfOf({ resource: CALENDAR, zoneUrl: ZONE, client: fakeZoneClient(), subjectTokens: store });
    expect((await failure(auth(session(keycardPrincipal())))).reason).toBe(FailureReason.SUBJECT_TOKEN_UNAVAILABLE);
  });

  describe("the caller's token bounds a cached exchange", () => {
    afterEach(() => {
      jest.useRealTimers();
    });

    it("a cached exchange is not served once the caller's token has expired", async () => {
      jest.useFakeTimers({ now: Date.now() });
      const client = fakeZoneClient({ expiresIn: 3600 });
      const auth = onBehalfOf({ resource: CALENDAR, zoneUrl: ZONE, client, subjectTokens: storeWith(validJwt(60)) });
      await auth(session(keycardPrincipal()));
      jest.setSystemTime(Date.now() + 120_000);
      expect((await failure(auth(session(keycardPrincipal())))).reason).toBe(FailureReason.SUBJECT_TOKEN_EXPIRED);
      expect(client.calls.exchanges).toHaveLength(1);
    });

    it("a cached exchange is not served once the caller's token is gone", async () => {
      const client = fakeZoneClient({ expiresIn: 3600 });
      const store = storeWith(validJwt());
      const auth = onBehalfOf({ resource: CALENDAR, zoneUrl: ZONE, client, subjectTokens: store });
      await auth(session(keycardPrincipal()));
      store.delete(`${ZONE}|user-1`);
      expect((await failure(auth(session(keycardPrincipal())))).reason).toBe(FailureReason.SUBJECT_TOKEN_UNAVAILABLE);
      expect(client.calls.exchanges).toHaveLength(1);
    });

    it("the cached exchange expires with the token it came from, so a fresh token is exchanged again", async () => {
      jest.useFakeTimers({ now: Date.now() });
      const client = fakeZoneClient({ expiresIn: 3600 });
      const store = storeWith(validJwt(60));
      const auth = onBehalfOf({ resource: CALENDAR, zoneUrl: ZONE, client, subjectTokens: store });
      await auth(session(keycardPrincipal()));
      jest.setSystemTime(Date.now() + 120_000);
      const fresh = validJwt(3600);
      store.set(`${ZONE}|user-1`, fresh);
      await auth(session(keycardPrincipal()));
      expect(client.calls.exchanges.map((e) => e.subjectToken)).toHaveLength(2);
      expect(client.calls.exchanges[1]?.subjectToken).toBe(fresh);
    });
  });

  it("row 21: a provider with client and no zoneUrl fails closed instead of skipping the zone check", async () => {
    const client = fakeZoneClient();
    const obo = onBehalfOf({ resource: CALENDAR, client, subjectTokens: storeWith(validJwt()) });
    expect((await failure(obo(session(keycardPrincipal())))).reason).toBe(FailureReason.PRINCIPAL_REQUIRED);
    const otherZone = keycardPrincipal({ attributes: { iss: "https://other-zone.example.com" } });
    const imp = impersonate({ resource: CALENDAR, client });
    expect((await failure(imp(session(otherZone)))).reason).toBe(FailureReason.PRINCIPAL_REQUIRED);
    expect(client.calls.exchanges).toHaveLength(0);
    expect(client.calls.impersonations).toHaveLength(0);
    const mapped = impersonate({ resource: CALENDAR, client, userIdentifier: () => "user-9" });
    await mapped(session(null));
    expect(client.calls.impersonations).toEqual([{ userIdentifier: "user-9", resource: CALENDAR }]);
  });

  it("row 41: a token placed on session.auth.attributes is ignored; only the store is read", async () => {
    const client = fakeZoneClient();
    const planted = validJwt();
    const auth = onBehalfOf({ resource: CALENDAR, zoneUrl: ZONE, client, subjectTokens: memorySubjectTokenStore() });
    const err = await failure(auth(session(keycardPrincipal({ attributes: { iss: ZONE, [SUBJECT_TOKEN_ATTRIBUTE]: planted } }))));
    expect(err.reason).toBe(FailureReason.SUBJECT_TOKEN_UNAVAILABLE);
    expect(err.message).toMatch(/different instance or has been pruned/);
    expect(err.message).not.toContain("attributes");
    expect(client.calls.exchanges).toHaveLength(0);
  });
});

describe("headersFor", () => {
  it("rows 19 and 20: shares the provider's cache and fails the same way", async () => {
    const client = fakeZoneClient({ expiresIn: 3600 });
    const auth = impersonate({ resource: CALENDAR, zoneUrl: ZONE, client });
    const fromTurn = await auth(session(keycardPrincipal()));
    const fromRoute = await headersFor(auth, { auth: keycardPrincipal() });
    expect(fromRoute).toEqual(fromTurn);
    expect(client.calls.impersonations).toHaveLength(1);
    expect((await failure(headersFor(auth, { auth: null }))).reason).toBe(FailureReason.PRINCIPAL_REQUIRED);
    const self = asSelf({ resource: CALENDAR, zoneUrl: ZONE, client });
    expect((await headersFor(self, { auth: null })).headers.authorization).toMatch(/^Bearer app-token/);
  });
});

interface RecordedTokenRequest {
  url: string;
  headers: Record<string, string>;
  body: URLSearchParams;
}

function stubZoneFetch(): {
  requests: RecordedTokenRequest[];
  allUrls: string[];
  restore: () => void;
} {
  const requests: RecordedTokenRequest[] = [];
  const allUrls: string[] = [];
  const originalFetch = globalThis.fetch;
  let serial = 0;

  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    allUrls.push(url);
    if (url.endsWith("/.well-known/oauth-authorization-server")) {
      return new Response(
        JSON.stringify({
          issuer: ZONE,
          token_endpoint: `${ZONE}/token`,
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    if (url === `${ZONE}/token`) {
      const headers: Record<string, string> = {};
      if (init?.headers) {
        const entries =
          init.headers instanceof Headers
            ? [...init.headers.entries()]
            : Array.isArray(init.headers)
              ? init.headers
              : Object.entries(init.headers);
        for (const [k, v] of entries) {
          headers[k.toLowerCase()] = v;
        }
      }
      const body = new URLSearchParams(typeof init?.body === "string" ? init.body : "");
      requests.push({ url, headers, body });
      serial += 1;
      return new Response(
        JSON.stringify({
          access_token: `zone-issued-${serial}`,
          token_type: "Bearer",
          expires_in: 3600,
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    throw new Error(`Unexpected fetch to ${url}`);
  }) as typeof fetch;

  return {
    requests,
    allUrls,
    restore: () => {
      globalThis.fetch = originalFetch;
    },
  };
}

describe("cursorWorkloadIdentity", () => {
  let restoreFetch: (() => void) | undefined;

  afterEach(() => {
    restoreFetch?.();
    restoreFetch = undefined;
  });

  it("row 42: each connection factory uses WorkloadIdentity with default and overridden audience and no Basic auth", async () => {
    const zone = stubZoneFetch();
    restoreFetch = zone.restore;

    const seenAudiences: string[] = [];
    let tokenSeq = 0;
    const getOidcToken = jest.fn(async (audience: string) => {
      seenAudiences.push(audience);
      tokenSeq += 1;
      return {
        token: `cursor-oidc-jwt-${tokenSeq}`,
        expiresAt: new Date(Date.now() + 300_000),
      };
    });

    const callerToken = validJwt(3600, { sub: "user-1" });
    const customAudience = "https://custom-aud.example.com";

    // Default audience (zone issuer URL, trailing slash stripped)
    const selfDefault = asSelf({
      resource: CALENDAR,
      zoneUrl: `${ZONE}/`,
      cursorWorkloadIdentity: { clientId: "v2-client-1", getOidcToken },
    });
    const oboDefault = onBehalfOf({
      resource: CALENDAR,
      zoneUrl: ZONE,
      subjectTokens: storeWith(callerToken),
      cursorWorkloadIdentity: { clientId: "v2-client-1", getOidcToken },
    });
    const impDefault = impersonate({
      resource: CALENDAR,
      zoneUrl: ZONE,
      cursorWorkloadIdentity: { clientId: "v2-client-1", getOidcToken },
    });

    // Helper is not called at definition time.
    expect(getOidcToken).not.toHaveBeenCalled();

    await selfDefault(session(null));
    await oboDefault(session(keycardPrincipal()));
    await impDefault(session(keycardPrincipal()));

    // Overridden audience
    const selfOverride = asSelf({
      resource: CALENDAR,
      zoneUrl: ZONE,
      cursorWorkloadIdentity: { clientId: "v2-client-2", audience: customAudience, getOidcToken },
    });
    const oboOverride = onBehalfOf({
      resource: CALENDAR,
      zoneUrl: ZONE,
      subjectTokens: storeWith(callerToken),
      cursorWorkloadIdentity: { clientId: "v2-client-2", audience: customAudience, getOidcToken },
    });
    const impOverride = impersonate({
      resource: CALENDAR,
      zoneUrl: ZONE,
      cursorWorkloadIdentity: { clientId: "v2-client-2", audience: customAudience, getOidcToken },
    });

    await selfOverride(session(null));
    await oboOverride(session(keycardPrincipal()));
    await impOverride(session(keycardPrincipal()));

    expect(seenAudiences).toEqual([
      ZONE,
      ZONE,
      ZONE,
      customAudience,
      customAudience,
      customAudience,
    ]);
    expect(zone.requests).toHaveLength(6);

    for (let i = 0; i < zone.requests.length; i += 1) {
      const req = zone.requests[i]!;
      expect(req.headers["authorization"]).toBeUndefined();
      expect(req.body.get("client_id")).toBe(i < 3 ? "v2-client-1" : "v2-client-2");
      expect(req.body.get("client_assertion")).toBe(`cursor-oidc-jwt-${i + 1}`);
      expect(req.body.get("client_assertion_type")).toBe(
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      );
    }

    // onBehalfOf preserves the caller's subject token unchanged.
    expect(zone.requests[1]!.body.get("subject_token")).toBe(callerToken);
    expect(zone.requests[4]!.body.get("subject_token")).toBe(callerToken);
  });

  it("row 43: invalid cursorWorkloadIdentity configurations fail at definition time without calling the helper", () => {
    const getOidcToken = jest.fn(async () => ({
      token: "unused",
      expiresAt: new Date(Date.now() + 300_000),
    }));
    const factories = [asSelf, onBehalfOf, impersonate] as const;

    for (const factory of factories) {
      // Combined with applicationCredential
      expect(() =>
        factory({
          resource: CALENDAR,
          zoneUrl: ZONE,
          applicationCredential: new AssertionCredential(),
          cursorWorkloadIdentity: { clientId: "v2-client-1", getOidcToken },
        }),
      ).toThrow(AuthProviderConfigurationError);

      // Combined with clientId / clientSecret shorthand
      expect(() =>
        factory({
          resource: CALENDAR,
          zoneUrl: ZONE,
          clientId: "app-1",
          clientSecret: "secret",
          cursorWorkloadIdentity: { clientId: "v2-client-1", getOidcToken },
        }),
      ).toThrow(AuthProviderConfigurationError);

      // Missing or blank clientId
      expect(() =>
        factory({
          resource: CALENDAR,
          zoneUrl: ZONE,
          cursorWorkloadIdentity: { clientId: "   ", getOidcToken },
        }),
      ).toThrow(AuthProviderConfigurationError);

      // Blank audience override
      expect(() =>
        factory({
          resource: CALENDAR,
          zoneUrl: ZONE,
          cursorWorkloadIdentity: { clientId: "v2-client-1", audience: "  ", getOidcToken },
        }),
      ).toThrow(AuthProviderConfigurationError);

      // Neither zoneUrl nor audience override
      expect(() =>
        factory({
          resource: CALENDAR,
          client: fakeZoneClient(),
          cursorWorkloadIdentity: { clientId: "v2-client-1", getOidcToken },
        }),
      ).toThrow(AuthProviderConfigurationError);
    }

    expect(getOidcToken).not.toHaveBeenCalled();
  });

  it("row 44: missing helper or undeclared audience surfaces WorkloadIdentityConfigurationError with no zone request", async () => {
    const zone = stubZoneFetch();
    restoreFetch = zone.restore;

    const undeclaredError = Object.assign(
      new Error("OIDC mint failed with HTTP 400: audience not allowed"),
      { name: "OidcTokenError", code: "failed", status: 400 },
    );
    const scenarios = [
      {
        name: "missing helper",
        cursorWorkloadIdentity: {
          clientId: "v2-client-1",
          loadSdk: async () => ({}),
        },
        pattern: /getOidcToken/,
      },
      {
        name: "undeclared audience",
        cursorWorkloadIdentity: {
          clientId: "v2-client-1",
          getOidcToken: async () => {
            throw undeclaredError;
          },
        },
        pattern: /hosting\.oidc\.audiences/,
      },
    ];

    for (const scenario of scenarios) {
      const providers = [
        {
          auth: asSelf({
            resource: CALENDAR,
            zoneUrl: ZONE,
            cursorWorkloadIdentity: scenario.cursorWorkloadIdentity,
          }),
          sess: session(null),
        },
        {
          auth: onBehalfOf({
            resource: CALENDAR,
            zoneUrl: ZONE,
            subjectTokens: storeWith(validJwt()),
            cursorWorkloadIdentity: scenario.cursorWorkloadIdentity,
          }),
          sess: session(keycardPrincipal()),
        },
        {
          auth: impersonate({
            resource: CALENDAR,
            zoneUrl: ZONE,
            cursorWorkloadIdentity: scenario.cursorWorkloadIdentity,
          }),
          sess: session(keycardPrincipal()),
        },
      ];

      for (const { auth, sess } of providers) {
        let caught: unknown;
        try {
          await auth(sess);
        } catch (error) {
          caught = error;
        }
        expect(caught).toBeInstanceOf(WorkloadIdentityConfigurationError);
        expect(caught).not.toBeInstanceOf(ConnectionAuthError);
        expect((caught as WorkloadIdentityConfigurationError).source).toBe(
          WORKLOAD_IDENTITY_SOURCE_CURSOR_DEPLOYMENT,
        );
        expect((caught as Error).message).toMatch(scenario.pattern);
      }
    }

    expect(zone.allUrls).toEqual([]);
  });

  it("row 45: self-hosted credentials do not load or call Cursor's OIDC helper", async () => {
    const zone = stubZoneFetch();
    restoreFetch = zone.restore;

    const self = asSelf({
      resource: CALENDAR,
      zoneUrl: ZONE,
      clientId: "app-1",
      clientSecret: "top-secret",
    });
    const obo = onBehalfOf({
      resource: CALENDAR,
      zoneUrl: ZONE,
      applicationCredential: new AssertionCredential(),
      subjectTokens: storeWith(validJwt()),
    });
    const imp = impersonate({
      resource: CALENDAR,
      zoneUrl: ZONE,
      clientId: "app-1",
      clientSecret: "top-secret",
    });

    await self(session(null));
    await obo(session(keycardPrincipal()));
    await imp(session(keycardPrincipal()));

    expect(zone.requests).toHaveLength(3);
    expect(zone.requests[0]!.headers["authorization"]).toMatch(/^Basic /);
    expect(zone.requests[0]!.body.get("client_assertion")).toBeNull();
    expect(zone.requests[1]!.body.get("client_assertion")).toBe("assertion-jwt");
    expect(zone.requests[2]!.headers["authorization"]).toMatch(/^Basic /);
  });
});
