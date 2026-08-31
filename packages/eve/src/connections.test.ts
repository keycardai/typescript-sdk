import { describe, expect, it } from "@jest/globals";
import {
  AuthProviderConfigurationError,
  ClientSecret,
  TokenType,
  type ApplicationCredential,
  type TokenExchangeRequest,
} from "@keycardai/oauth";
import type { ConnectionPrincipal } from "eve/connections";

import { asSelf, impersonate, onBehalfOf } from "./connections.js";
import { AuthorizationFailedError, FailureReason } from "./errors.js";
import { memorySubjectTokenStore, SUBJECT_TOKEN_ATTRIBUTE } from "./subjectTokens.js";
import {
  appPrincipal,
  connectionContext,
  expiredJwt,
  fakeZoneClient,
  unsignedJwt,
  userPrincipal,
  validJwt,
} from "./testing/testUtils.js";

const ZONE = "https://zone.example.com";
const CALENDAR = "https://calendar.example.com";
const connection = connectionContext();

/** A store holding one subject token for the principal used across the suite. */
function storeWith(token: string) {
  const store = memorySubjectTokenStore();
  store.set(`${ZONE}|user-1`, token);
  return store;
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
      subjectTokenType: TokenType.ACCESS_TOKEN,
      clientAssertion: "assertion.jwt.value",
      clientAssertionType: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      clientId: "workload-client",
    };
  }
}

describe("onBehalfOf", () => {
  it("exchanges the current user's subject token for the resource", async () => {
    const subjectToken = validJwt(3600);
    const client = fakeZoneClient({ expiresIn: 300 });
    const auth = onBehalfOf({ resource: CALENDAR, client, subjectTokens: storeWith(subjectToken) });

    const result = await auth.getToken({ principal: userPrincipal(), connection });

    expect(auth.principalType).toBe("user");
    expect(client.calls.exchanges).toEqual([
      { subjectToken, resource: CALENDAR, subjectTokenType: TokenType.ACCESS_TOKEN },
    ]);
    expect(client.calls.impersonations).toEqual([]);
    expect(client.calls.clientCredentials).toEqual([]);
    expect(result.token).toBe(`exchanged-token-for-${CALENDAR}`);
    expect(result.expiresAt).toBeGreaterThan(Date.now());
  });

  it("reads the subject token from principal attributes when retention is attributes", async () => {
    const subjectToken = validJwt(3600);
    const client = fakeZoneClient();
    const auth = onBehalfOf({ resource: CALENDAR, client });

    await auth.getToken({
      principal: userPrincipal("user-9", ZONE, { [SUBJECT_TOKEN_ATTRIBUTE]: subjectToken }),
      connection,
    });

    expect(client.calls.exchanges[0]?.subjectToken).toBe(subjectToken);
  });

  it("uses the turn's current principal, not the session initiator", async () => {
    const initiatorToken = validJwt(3600, { sub: "initiator" });
    const currentToken = validJwt(3600, { sub: "current" });
    const store = memorySubjectTokenStore();
    store.set(`${ZONE}|initiator`, initiatorToken);
    store.set(`${ZONE}|current`, currentToken);
    const client = fakeZoneClient();
    const auth = onBehalfOf({ resource: CALENDAR, client, subjectTokens: store });

    // eve projects `ctx.session.auth.current` onto the connection principal.
    await auth.getToken({ principal: userPrincipal("current", ZONE), connection });

    expect(client.calls.exchanges[0]?.subjectToken).toBe(currentToken);
  });

  it("forwards requested scopes to the exchange", async () => {
    const client = fakeZoneClient();
    const auth = onBehalfOf({
      resource: CALENDAR,
      client,
      requestScopes: ["calendar.read", "calendar.write"],
      subjectTokens: storeWith(validJwt(3600)),
    });

    await auth.getToken({ principal: userPrincipal(), connection });

    expect(client.calls.exchanges[0]?.scope).toBe("calendar.read calendar.write");
  });

  it("fails with principal_required under an app principal, without acquiring", async () => {
    const client = fakeZoneClient();
    const auth = onBehalfOf({ resource: CALENDAR, client, subjectTokens: storeWith(validJwt(3600)) });

    await expect(
      auth.getToken({ principal: appPrincipal(), connection }),
    ).rejects.toMatchObject({
      name: "ConnectionAuthorizationFailedError",
      reason: FailureReason.PRINCIPAL_REQUIRED,
      retryable: false,
    });
    expect(client.calls).toEqual({ exchanges: [], impersonations: [], clientCredentials: [] });
  });

  it("fails when no subject token was retained, never reaching for app authority", async () => {
    const client = fakeZoneClient();
    const auth = onBehalfOf({
      resource: CALENDAR,
      client,
      clientId: "agent",
      clientSecret: "shh",
      subjectTokens: memorySubjectTokenStore(),
    });

    await expect(auth.getToken({ principal: userPrincipal(), connection })).rejects.toMatchObject({
      reason: FailureReason.SUBJECT_TOKEN_UNAVAILABLE,
      retryable: false,
    });
    expect(client.calls.clientCredentials).toEqual([]);
    expect(client.calls.exchanges).toEqual([]);
  });

  it("routes an expired subject token to sign-in instead of exchanging it", async () => {
    const client = fakeZoneClient();
    const auth = onBehalfOf({
      resource: CALENDAR,
      client,
      subjectTokens: storeWith(expiredJwt()),
    });

    await expect(auth.getToken({ principal: userPrincipal(), connection })).rejects.toMatchObject({
      reason: FailureReason.SUBJECT_TOKEN_EXPIRED,
      retryable: false,
    });
    expect(client.calls.exchanges).toEqual([]);
  });

  it("passes opaque and exp-less subject tokens to the zone unchanged", async () => {
    for (const subjectToken of ["opaque-zone-token", unsignedJwt({ sub: "user-1" })]) {
      const client = fakeZoneClient();
      const auth = onBehalfOf({
        resource: CALENDAR,
        client,
        subjectTokens: storeWith(subjectToken),
      });

      await auth.getToken({ principal: userPrincipal(), connection });

      expect(client.calls.exchanges[0]?.subjectToken).toBe(subjectToken);
    }
  });

  it("wraps a zone refusal as a terminal authorization failure", async () => {
    const client = fakeZoneClient({ failResources: { [CALENDAR]: new Error("access_denied") } });
    const auth = onBehalfOf({ resource: CALENDAR, client, subjectTokens: storeWith(validJwt(3600)) });

    const failure = await auth
      .getToken({ principal: userPrincipal(), connection })
      .catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(AuthorizationFailedError);
    expect(failure).toMatchObject({ reason: FailureReason.ACQUISITION_FAILED, retryable: false });
  });

  it("forwards an assertion credential's client assertion on the exchange", async () => {
    const client = fakeZoneClient();
    const auth = onBehalfOf({
      resource: CALENDAR,
      client,
      applicationCredential: new AssertionCredential(),
      subjectTokens: storeWith(validJwt(3600)),
    });

    await auth.getToken({ principal: userPrincipal(), connection });

    expect(client.calls.exchanges[0]).toMatchObject({
      clientAssertion: "assertion.jwt.value",
      clientAssertionType: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      clientId: "workload-client",
    });
  });
});

describe("impersonate", () => {
  it("uses the substitute-user path, not on-behalf-of exchange", async () => {
    const client = fakeZoneClient();
    const auth = impersonate({
      resource: CALENDAR,
      client,
      userIdentifier: "ops@example.com",
      requestScopes: "calendar.read",
    });

    const result = await auth.getToken({ principal: appPrincipal(), connection });

    expect(auth.principalType).toBe("app");
    expect(client.calls.impersonations).toEqual([
      { userIdentifier: "ops@example.com", resource: CALENDAR, scope: "calendar.read" },
    ]);
    expect(client.calls.exchanges).toEqual([]);
    expect(result.token).toBe(`impersonated-token-for-${CALENDAR}`);
  });

  it("is user-scoped when the identifier is derived from the caller", async () => {
    const client = fakeZoneClient();
    const auth = impersonate({
      resource: CALENDAR,
      client,
      userIdentifier: (principal: ConnectionPrincipal) =>
        principal.type === "user" ? principal.id : "",
    });

    expect(auth.principalType).toBe("user");
    await auth.getToken({ principal: userPrincipal("user-7"), connection });
    expect(client.calls.impersonations[0]?.userIdentifier).toBe("user-7");

    await expect(auth.getToken({ principal: appPrincipal(), connection })).rejects.toMatchObject({
      reason: FailureReason.PRINCIPAL_REQUIRED,
    });
  });

  it("rejects an empty user identifier at definition time", () => {
    expect(() => impersonate({ resource: CALENDAR, zoneUrl: ZONE, userIdentifier: "  " })).toThrow(
      AuthProviderConfigurationError,
    );
  });
});

describe("asSelf", () => {
  it("runs client credentials, not exchange or impersonation", async () => {
    const client = fakeZoneClient();
    const auth = asSelf({
      resource: CALENDAR,
      client,
      clientId: "agent",
      clientSecret: "shh",
      requestScopes: ["reports.read"],
    });

    const result = await auth.getToken({ principal: appPrincipal(), connection });

    expect(auth.principalType).toBe("app");
    expect(client.calls.clientCredentials).toEqual([
      { resource: CALENDAR, scope: "reports.read" },
    ]);
    expect(client.calls.exchanges).toEqual([]);
    expect(client.calls.impersonations).toEqual([]);
    expect(result.token).toBe(`app-token-for-${CALENDAR}`);
  });

  it("builds a client-secret credential from the shorthand", async () => {
    const client = fakeZoneClient();
    const auth = asSelf({ resource: CALENDAR, client, clientId: "agent", clientSecret: "shh" });

    await auth.getToken({ principal: appPrincipal(), connection });

    // `ClientSecret` authenticates at the HTTP layer, so the request body
    // carries no client-auth fields.
    expect(client.calls.clientCredentials[0]).toEqual({ resource: CALENDAR });
  });

  it("forwards assertion client-auth fields on the client-credentials request", async () => {
    const client = fakeZoneClient();
    const auth = asSelf({
      resource: CALENDAR,
      client,
      applicationCredential: new AssertionCredential(),
    });

    await auth.getToken({ principal: appPrincipal(), connection });

    expect(client.calls.clientCredentials[0]).toEqual({
      resource: CALENDAR,
      clientAssertion: "assertion.jwt.value",
      clientAssertionType: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      clientId: "workload-client",
    });
  });

  it("surfaces a global zone failure as an authorization failure", async () => {
    const client = fakeZoneClient({ fail: new Error("zone unreachable") });
    const auth = asSelf({ resource: CALENDAR, client });

    await expect(auth.getToken({ principal: appPrincipal(), connection })).rejects.toMatchObject({
      name: "ConnectionAuthorizationFailedError",
      reason: FailureReason.ACQUISITION_FAILED,
    });
  });
});

describe("factory configuration", () => {
  it("requires a resource", () => {
    expect(() => asSelf({ resource: "", zoneUrl: ZONE })).toThrow(
      AuthProviderConfigurationError,
    );
  });

  it("requires a zone URL or an injected client", () => {
    expect(() => onBehalfOf({ resource: CALENDAR })).toThrow(AuthProviderConfigurationError);
  });

  it("uses the injected client instead of building one for zoneUrl", async () => {
    const client = fakeZoneClient();
    const auth = onBehalfOf({
      resource: CALENDAR,
      zoneUrl: "https://unreachable.invalid",
      client,
      subjectTokens: storeWith(validJwt(3600)),
    });

    await auth.getToken({ principal: userPrincipal(), connection });

    expect(client.calls.exchanges).toHaveLength(1);
  });

  it("rejects two credential paths at once", () => {
    expect(() =>
      asSelf({
        resource: CALENDAR,
        zoneUrl: ZONE,
        applicationCredential: new ClientSecret("id", "secret"),
        clientId: "id",
        clientSecret: "secret",
      }),
    ).toThrow(AuthProviderConfigurationError);
  });

  it("rejects half of the client-secret shorthand", () => {
    expect(() => asSelf({ resource: CALENDAR, zoneUrl: ZONE, clientId: "id" })).toThrow(
      AuthProviderConfigurationError,
    );
  });
});
