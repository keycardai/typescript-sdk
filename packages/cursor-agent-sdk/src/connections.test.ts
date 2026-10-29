import { describe, expect, it } from "@jest/globals";
import type { AuthContext } from "@grok/agent-sdk";
import {
  AuthProviderConfigurationError,
  type ApplicationCredential,
  type TokenExchangeRequest,
} from "@keycardai/oauth";

import { asSelf, headersFor, impersonate, onBehalfOf } from "./connections.js";
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

  it("row 33: the attributes retention mode is read from the principal", async () => {
    const client = fakeZoneClient();
    const token = validJwt();
    const auth = onBehalfOf({ resource: CALENDAR, zoneUrl: ZONE, client, subjectTokens: memorySubjectTokenStore() });
    await auth(session(keycardPrincipal({ attributes: { iss: ZONE, [SUBJECT_TOKEN_ATTRIBUTE]: token } })));
    expect(client.calls.exchanges[0]?.subjectToken).toBe(token);
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
