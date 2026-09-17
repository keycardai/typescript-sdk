import { beforeEach, describe, expect, it } from "@jest/globals";
import {
  AuthProviderConfigurationError,
  AuthorizationDeniedError,
  RefreshGrantError,
  StateMismatchError,
  type AuthorizationRedirect,
  type BeginAuthorizationOptions,
  type CompleteAuthorizationOptions,
  type RefreshAuthorizationOptions,
  type TokenResponse,
} from "@keycardai/oauth";
import type { AuthorizationCallback } from "eve/connections";

import { FailureReason } from "./errors.js";
import {
  interactive,
  memoryAuthorizedTokenStore,
  resetInteractiveDefinitions,
  type RegisterAttemptClientOptions,
  type RegisteredClient,
  type WebAppFlow,
} from "./interactive.js";
import {
  appPrincipal,
  connectionContext,
  userPrincipal,
} from "./testing/testUtils.js";

const CALENDAR = "https://calendar.example.com";
const CALLBACK = "https://agent.example.com/connections/calendar/callback";
const connection = connectionContext();
const PRINCIPAL_KEY = "https://zone.example.com|user-1";

// Every test defines connections afresh, most of them under the default name.
beforeEach(resetInteractiveDefinitions);

interface RecordingFlow extends WebAppFlow {
  readonly begins: BeginAuthorizationOptions[];
  readonly completes: CompleteAuthorizationOptions[];
  readonly registrations: RegisterAttemptClientOptions[];
  readonly refreshes: RefreshAuthorizationOptions[];
}

function recordingFlow(
  options: {
    completion?: Error | TokenResponse;
    registration?: Error | RegisteredClient;
    refresh?: Error | TokenResponse;
  } = {},
): RecordingFlow {
  const begins: BeginAuthorizationOptions[] = [];
  const completes: CompleteAuthorizationOptions[] = [];
  const registrations: RegisterAttemptClientOptions[] = [];
  const refreshes: RefreshAuthorizationOptions[] = [];
  return {
    begins,
    completes,
    registrations,
    refreshes,
    async begin(beginOptions): Promise<AuthorizationRedirect> {
      begins.push(beginOptions);
      return {
        url: `https://zone.example.com/authorize?state=state-1&redirect_uri=${beginOptions.redirectUri}`,
        state: "state-1",
        codeVerifier: "verifier-1",
        resources: [...(beginOptions.resources ?? [])],
      };
    },
    async complete(completeOptions): Promise<TokenResponse> {
      completes.push(completeOptions);
      const completion = options.completion;
      if (completion instanceof Error) throw completion;
      return (
        completion ?? {
          accessToken: "granted-token",
          tokenType: "Bearer",
          expiresIn: 900,
        }
      );
    },
    async register(registerOptions): Promise<RegisteredClient> {
      registrations.push(registerOptions);
      const registration = options.registration;
      if (registration instanceof Error) throw registration;
      // A different client per attempt, so a test can tell which one redeemed.
      return (
        registration ?? { clientId: `attempt-client-${registrations.length}` }
      );
    },
    async refresh(refreshOptions): Promise<TokenResponse> {
      refreshes.push(refreshOptions);
      const refresh = options.refresh;
      if (refresh instanceof Error) throw refresh;
      return (
        refresh ?? {
          accessToken: "refreshed-token",
          tokenType: "Bearer",
          expiresIn: 900,
          refreshToken: "rotated-refresh",
        }
      );
    },
  };
}

/** Runs one attempt through begin and complete for `principal`. */
async function authorize(
  auth: ReturnType<typeof interactive>,
  principal = userPrincipal(),
  callbackUrl = CALLBACK,
): Promise<void> {
  const started = await auth.startAuthorization({
    principal,
    connection,
    callbackUrl,
  });
  await auth.completeAuthorization({
    principal,
    connection,
    callbackUrl,
    resume: started.resume,
    callback: callback({ code: "auth-code", state: "state-1" }),
  });
}

/** A flow with no `register`, i.e. one that only supports a static client. */
function staticOnlyFlow(): WebAppFlow {
  const { begin, complete } = recordingFlow();
  return { begin, complete };
}

function callback(params: Record<string, string>): AuthorizationCallback {
  return { params, method: "GET" };
}

describe("interactive", () => {
  it("parks the turn through eve's authorization-required error", async () => {
    const auth = interactive({ resource: CALENDAR, flow: recordingFlow() });

    await expect(
      auth.getToken({ principal: userPrincipal(), connection }),
    ).rejects.toMatchObject({
      name: "ConnectionAuthorizationRequiredError",
      connectionName: CALENDAR,
    });
    expect(auth.principalType).toBe("user");
  });

  it("keeps off the keys eve's connection validator rejects", async () => {
    const auth = interactive({
      resource: CALENDAR,
      connectionName: "Calendar",
      flow: recordingFlow(),
    });

    // eve validates an authored connection's `auth` against this closed list;
    // a key outside it (`displayName` is the one this package used to set)
    // fails the build for every connection using it.
    const allowed = [
      "completeAuthorization",
      "evict",
      "getToken",
      "principalType",
      "startAuthorization",
      "vercelConnect",
    ];
    expect(Object.keys(auth).filter((key) => !allowed.includes(key))).toEqual(
      [],
    );

    // The name still reaches the sign-in prompt, on the challenge, which is
    // where eve's stampChallengeDisplayName falls back to.
    const started = await auth.startAuthorization({
      principal: userPrincipal(),
      connection,
      callbackUrl: CALLBACK,
    });
    expect(started.challenge.displayName).toBe("Calendar");
  });

  it("begins the flow against eve's callback URL with the resource list", async () => {
    const flow = recordingFlow();
    const auth = interactive({
      resource: CALENDAR,
      clientId: "web-client",
      zoneUrl: "https://zone.example.com",
      requestScopes: ["calendar.read"],
      additionalResources: ["https://docs.example.com"],
      flow,
    });

    const started = await auth.startAuthorization({
      principal: userPrincipal(),
      connection,
      callbackUrl: CALLBACK,
    });

    expect(flow.begins).toEqual([
      {
        clientId: "web-client",
        redirectUri: CALLBACK,
        resources: [CALENDAR, "https://docs.example.com"],
        scopes: ["calendar.read"],
      },
    ]);
    expect(started.challenge.url).toContain(
      "https://zone.example.com/authorize",
    );
    expect(started.resume).toEqual({
      state: "state-1",
      codeVerifier: "verifier-1",
      resources: [CALENDAR, "https://docs.example.com"],
      callbackUrl: CALLBACK,
      clientId: "web-client",
    });
    // A configured client is used as given; nothing is registered for it.
    expect(flow.registrations).toEqual([]);
    // eve journals the resume value, so it has to survive a JSON round trip.
    expect(JSON.parse(JSON.stringify(started.resume))).toEqual(started.resume);
  });

  it("completes the callback and hands eve the token", async () => {
    const flow = recordingFlow();
    const tokens = memoryAuthorizedTokenStore();
    const auth = interactive({
      resource: CALENDAR,
      clientId: "web-client",
      clientSecret: "shh",
      zoneUrl: "https://zone.example.com",
      tokens,
      flow,
    });
    const started = await auth.startAuthorization({
      principal: userPrincipal(),
      connection,
      callbackUrl: CALLBACK,
    });

    const result = await auth.completeAuthorization({
      principal: userPrincipal(),
      connection,
      callbackUrl: CALLBACK,
      resume: started.resume,
      callback: callback({ code: "auth-code", state: "state-1" }),
    });

    expect(flow.completes).toEqual([
      {
        callbackParams: { code: "auth-code", state: "state-1" },
        state: "state-1",
        codeVerifier: "verifier-1",
        clientId: "web-client",
        redirectUri: CALLBACK,
        clientSecret: "shh",
      },
    ]);
    expect(result.token).toBe("granted-token");
    expect(result.expiresAt).toBeGreaterThan(Date.now());

    // The settled grant is what makes the next step reuse it instead of parking.
    const reused = await auth.getToken({
      principal: userPrincipal(),
      connection,
    });
    expect(reused.token).toBe("granted-token");
  });

  it("re-parks a resume that never completed authorization", async () => {
    const flow = recordingFlow();
    const auth = interactive({ resource: CALENDAR, flow });

    await auth.startAuthorization({
      principal: userPrincipal(),
      connection,
      callbackUrl: CALLBACK,
    });

    // The turn resumes with the begin step journaled but no callback settled.
    await expect(
      auth.getToken({ principal: userPrincipal(), connection }),
    ).rejects.toMatchObject({
      name: "ConnectionAuthorizationRequiredError",
    });
    expect(flow.completes).toEqual([]);
  });

  it("keeps a denied authorization from yielding a token", async () => {
    const flow = recordingFlow({
      completion: new AuthorizationDeniedError(
        "access_denied",
        "User denied the request",
      ),
    });
    const auth = interactive({ resource: CALENDAR, flow });
    const started = await auth.startAuthorization({
      principal: userPrincipal(),
      connection,
      callbackUrl: CALLBACK,
    });

    await expect(
      auth.completeAuthorization({
        principal: userPrincipal(),
        connection,
        callbackUrl: CALLBACK,
        resume: started.resume,
        callback: callback({ error: "access_denied", state: "state-1" }),
      }),
    ).rejects.toMatchObject({
      name: "ConnectionAuthorizationFailedError",
      reason: FailureReason.ACCESS_DENIED,
      retryable: false,
    });

    await expect(
      auth.getToken({ principal: userPrincipal(), connection }),
    ).rejects.toMatchObject({
      name: "ConnectionAuthorizationRequiredError",
    });
  });

  it("rejects a callback whose state does not match the begin step", async () => {
    const flow = recordingFlow({ completion: new StateMismatchError() });
    const auth = interactive({ resource: CALENDAR, flow });
    const started = await auth.startAuthorization({
      principal: userPrincipal(),
      connection,
      callbackUrl: CALLBACK,
    });

    await expect(
      auth.completeAuthorization({
        principal: userPrincipal(),
        connection,
        callbackUrl: CALLBACK,
        resume: started.resume,
        callback: callback({ code: "auth-code", state: "forged" }),
      }),
    ).rejects.toMatchObject({
      reason: FailureReason.INVALID_CALLBACK,
      retryable: false,
    });
  });

  it("rejects a callback that arrives with no journaled resume state", async () => {
    const flow = recordingFlow();
    const auth = interactive({ resource: CALENDAR, flow });

    await expect(
      auth.completeAuthorization({
        principal: userPrincipal(),
        connection,
        callbackUrl: CALLBACK,
        callback: callback({ code: "auth-code" }),
      }),
    ).rejects.toMatchObject({ reason: FailureReason.INVALID_CALLBACK });
    expect(flow.completes).toEqual([]);
  });

  it("keeps grants separate per principal", async () => {
    const auth = interactive({ resource: CALENDAR, flow: recordingFlow() });
    const started = await auth.startAuthorization({
      principal: userPrincipal("user-1"),
      connection,
      callbackUrl: CALLBACK,
    });
    await auth.completeAuthorization({
      principal: userPrincipal("user-1"),
      connection,
      callbackUrl: CALLBACK,
      resume: started.resume,
      callback: callback({ code: "auth-code", state: "state-1" }),
    });

    await expect(
      auth.getToken({ principal: userPrincipal("user-2"), connection }),
    ).rejects.toMatchObject({ name: "ConnectionAuthorizationRequiredError" });
  });

  it("drops a rejected credential when eve evicts it", async () => {
    const auth = interactive({ resource: CALENDAR, flow: recordingFlow() });
    const started = await auth.startAuthorization({
      principal: userPrincipal(),
      connection,
      callbackUrl: CALLBACK,
    });
    await auth.completeAuthorization({
      principal: userPrincipal(),
      connection,
      callbackUrl: CALLBACK,
      resume: started.resume,
      callback: callback({ code: "auth-code", state: "state-1" }),
    });

    await auth.evict?.({ principal: userPrincipal(), connection });

    await expect(
      auth.getToken({ principal: userPrincipal(), connection }),
    ).rejects.toMatchObject({
      name: "ConnectionAuthorizationRequiredError",
    });
  });

  it("fails closed when authorization starts without a user principal", async () => {
    const auth = interactive({ resource: CALENDAR, flow: recordingFlow() });

    await expect(
      auth.startAuthorization({
        principal: appPrincipal(),
        connection,
        callbackUrl: CALLBACK,
      }),
    ).rejects.toMatchObject({ reason: FailureReason.PRINCIPAL_REQUIRED });
  });

  it("requires a zone URL unless a flow is injected", () => {
    expect(() => interactive({ resource: CALENDAR })).toThrow(
      AuthProviderConfigurationError,
    );
    expect(() => interactive({ resource: "", flow: recordingFlow() })).toThrow(
      AuthProviderConfigurationError,
    );
  });

  it("takes a zone URL alone, because the client is registered per attempt", () => {
    expect(() =>
      interactive({ resource: CALENDAR, zoneUrl: "https://zone.example.com" }),
    ).not.toThrow();
  });

  it("refuses a flow that can neither register a client nor be given one", () => {
    expect(() =>
      interactive({ resource: CALENDAR, flow: staticOnlyFlow() }),
    ).toThrow(AuthProviderConfigurationError);
    // The same flow is fine once a client is configured.
    expect(() =>
      interactive({
        resource: CALENDAR,
        clientId: "web-client",
        flow: staticOnlyFlow(),
      }),
    ).not.toThrow();
  });
});

/**
 * eve mints a new callback URL per attempt, and RFC 9700 requires the server to
 * match `redirect_uri` by exact string comparison. These cover the arrangement
 * that satisfies both: the client is registered alongside the callback it is
 * bound to, and the code is redeemed by that same client.
 */
describe("interactive per-attempt client registration", () => {
  it("registers a client bound to the callback URL of that attempt", async () => {
    const flow = recordingFlow();
    const auth = interactive({
      resource: CALENDAR,
      zoneUrl: "https://zone.example.com",
      connectionName: "Calendar",
      requestScopes: ["calendar.read"],
      flow,
    });

    const started = await auth.startAuthorization({
      principal: userPrincipal(),
      connection,
      callbackUrl: CALLBACK,
    });

    expect(flow.registrations).toEqual([
      {
        redirectUri: CALLBACK,
        clientName: "Calendar",
        scopes: ["calendar.read"],
      },
    ]);
    // The authorization request runs as the client just registered for it.
    expect(flow.begins[0]?.clientId).toBe("attempt-client-1");
    expect(started.resume.clientId).toBe("attempt-client-1");
  });

  it("gives each attempt its own client and callback", async () => {
    const flow = recordingFlow();
    const auth = interactive({
      resource: CALENDAR,
      zoneUrl: "https://zone.example.com",
      flow,
    });
    const second = `${CALLBACK}/attempt-2`;

    await auth.startAuthorization({
      principal: userPrincipal(),
      connection,
      callbackUrl: CALLBACK,
    });
    await auth.startAuthorization({
      principal: userPrincipal(),
      connection,
      callbackUrl: second,
    });

    expect(flow.registrations.map((entry) => entry.redirectUri)).toEqual([
      CALLBACK,
      second,
    ]);
    expect(flow.begins.map((entry) => entry.clientId)).toEqual([
      "attempt-client-1",
      "attempt-client-2",
    ]);
  });

  it("redeems the code as the client that made the request", async () => {
    const flow = recordingFlow();
    const auth = interactive({
      resource: CALENDAR,
      zoneUrl: "https://zone.example.com",
      flow,
    });
    const started = await auth.startAuthorization({
      principal: userPrincipal(),
      connection,
      callbackUrl: CALLBACK,
    });

    // A second attempt registers a different client. The first callback must
    // still redeem as the client its own authorization request ran as.
    await auth.startAuthorization({
      principal: userPrincipal(),
      connection,
      callbackUrl: `${CALLBACK}/attempt-2`,
    });

    const result = await auth.completeAuthorization({
      principal: userPrincipal(),
      connection,
      callbackUrl: CALLBACK,
      resume: started.resume,
      callback: callback({ code: "auth-code", state: "state-1" }),
    });

    expect(flow.completes[0]?.clientId).toBe("attempt-client-1");
    expect(flow.completes[0]?.redirectUri).toBe(CALLBACK);
    expect(result.token).toBe("granted-token");
  });

  it("journals no credential into eve's resume state", async () => {
    const flow = recordingFlow();
    const auth = interactive({
      resource: CALENDAR,
      zoneUrl: "https://zone.example.com",
      flow,
    });

    const started = await auth.startAuthorization({
      principal: userPrincipal(),
      connection,
      callbackUrl: CALLBACK,
    });

    // The resume crosses a durable step boundary, so it must survive JSON and
    // must not carry a client secret.
    expect(JSON.parse(JSON.stringify(started.resume))).toEqual(started.resume);
    expect(Object.keys(started.resume).sort()).toEqual([
      "callbackUrl",
      "clientId",
      "codeVerifier",
      "resources",
      "state",
    ]);
  });

  it("abandons the attempt when the server issues a confidential client", async () => {
    const flow = recordingFlow({
      registration: {
        clientId: "attempt-client-1",
        clientSecret: "issued-secret",
      },
    });
    const auth = interactive({
      resource: CALENDAR,
      zoneUrl: "https://zone.example.com",
      flow,
    });

    await expect(
      auth.startAuthorization({
        principal: userPrincipal(),
        connection,
        callbackUrl: CALLBACK,
      }),
    ).rejects.toMatchObject({
      name: "ConnectionAuthorizationFailedError",
      reason: FailureReason.ACQUISITION_FAILED,
      retryable: false,
    });

    // Nothing proceeded, so the secret never reached a journaled resume.
    expect(flow.begins).toEqual([]);
  });

  it("surfaces a failed registration as a retryable authorization failure", async () => {
    const flow = recordingFlow({
      registration: new Error("registration endpoint returned 503"),
    });
    const auth = interactive({
      resource: CALENDAR,
      zoneUrl: "https://zone.example.com",
      flow,
    });

    await expect(
      auth.startAuthorization({
        principal: userPrincipal(),
        connection,
        callbackUrl: CALLBACK,
      }),
    ).rejects.toMatchObject({
      name: "ConnectionAuthorizationFailedError",
      reason: FailureReason.ACQUISITION_FAILED,
      retryable: true,
    });
  });

  it("sends no client secret for a registered client", async () => {
    const flow = recordingFlow();
    const auth = interactive({
      resource: CALENDAR,
      zoneUrl: "https://zone.example.com",
      // Configured but unusable: it belongs to a static client that is not in play.
      clientSecret: "shh",
      flow,
    });
    const started = await auth.startAuthorization({
      principal: userPrincipal(),
      connection,
      callbackUrl: CALLBACK,
    });

    await auth.completeAuthorization({
      principal: userPrincipal(),
      connection,
      callbackUrl: CALLBACK,
      resume: started.resume,
      callback: callback({ code: "auth-code", state: "state-1" }),
    });

    expect(flow.completes[0]).not.toHaveProperty("clientSecret");
  });
});

/**
 * A completed authorization is kept as a grant keyed by principal and
 * resource, refreshed silently while it holds a refresh token, and never shared
 * through a connection name.
 */
describe("interactive grant lifecycle", () => {
  it("serves later steps from the stored grant without a second sign-in", async () => {
    const flow = recordingFlow();
    const auth = interactive({ resource: CALENDAR, flow });
    await authorize(auth);

    const first = await auth.getToken({
      principal: userPrincipal(),
      connection,
    });
    const second = await auth.getToken({
      principal: userPrincipal(),
      connection,
    });

    expect(first.token).toBe("granted-token");
    expect(second.token).toBe("granted-token");
    expect(flow.begins).toHaveLength(1);
    expect(flow.refreshes).toEqual([]);
  });

  it("finds the grant from a second definition over the same injected store", async () => {
    const tokens = memoryAuthorizedTokenStore();
    const first = interactive({
      resource: CALENDAR,
      connectionName: "Calendar A",
      tokens,
      flow: recordingFlow(),
    });
    await authorize(first);

    // A second process plugging the same durable store: a fresh definition,
    // fresh flow, nothing in memory but the store.
    const flow = recordingFlow();
    const second = interactive({
      resource: CALENDAR,
      connectionName: "Calendar B",
      tokens,
      flow,
    });

    const result = await second.getToken({
      principal: userPrincipal(),
      connection,
    });
    expect(result.token).toBe("granted-token");
    expect(flow.begins).toEqual([]);
  });

  it("refreshes a near-expiry grant silently and stores the rotated pair", async () => {
    const flow = recordingFlow({
      completion: {
        accessToken: "granted-token",
        tokenType: "Bearer",
        expiresIn: 30,
        refreshToken: "refresh-1",
        scope: "calendar.read",
      },
    });
    const tokens = memoryAuthorizedTokenStore();
    const auth = interactive({
      resource: CALENDAR,
      requestScopes: ["calendar.read"],
      tokens,
      flow,
    });
    await authorize(auth);

    const result = await auth.getToken({
      principal: userPrincipal(),
      connection,
    });

    expect(result.token).toBe("refreshed-token");
    expect(flow.refreshes).toEqual([
      {
        refreshToken: "refresh-1",
        clientId: "attempt-client-1",
        resources: [CALENDAR],
        scopes: ["calendar.read"],
      },
    ]);
    expect(flow.refreshes[0]).not.toHaveProperty("clientSecret");
    expect(flow.begins).toHaveLength(1);

    const held = await tokens.list(PRINCIPAL_KEY);
    expect(held).toHaveLength(1);
    expect(held[0]).toMatchObject({
      accessToken: "refreshed-token",
      refreshToken: "rotated-refresh",
      clientId: "attempt-client-1",
    });
    expect(held[0]?.expiresAt).toBeGreaterThan(Date.now() + 60_000);
  });

  it("removes the grant and parks when the zone refuses the refresh", async () => {
    const flow = recordingFlow({
      completion: {
        accessToken: "granted-token",
        tokenType: "Bearer",
        expiresIn: 30,
        refreshToken: "refresh-1",
      },
      refresh: new RefreshGrantError("invalid_grant", "refresh token revoked", {
        retryable: false,
        status: 400,
      }),
    });
    const tokens = memoryAuthorizedTokenStore();
    const auth = interactive({ resource: CALENDAR, tokens, flow });
    await authorize(auth);

    await expect(
      auth.getToken({ principal: userPrincipal(), connection }),
    ).rejects.toMatchObject({
      name: "ConnectionAuthorizationRequiredError",
      connectionName: CALENDAR,
    });
    expect(await tokens.list(PRINCIPAL_KEY)).toEqual([]);

    // The next completed authorization stores a fresh grant.
    const recovered = recordingFlow();
    const again = interactive({
      resource: CALENDAR,
      connectionName: "Calendar again",
      tokens,
      flow: recovered,
    });
    await authorize(again);
    const result = await again.getToken({
      principal: userPrincipal(),
      connection,
    });
    expect(result.token).toBe("granted-token");
  });

  it("surfaces a failed refresh with the zone's retryability", async () => {
    const flow = recordingFlow({
      completion: {
        accessToken: "granted-token",
        tokenType: "Bearer",
        expiresIn: 30,
        refreshToken: "refresh-1",
      },
      refresh: new RefreshGrantError("invalid_response", "HTTP 503", {
        retryable: true,
        status: 503,
      }),
    });
    const tokens = memoryAuthorizedTokenStore();
    const auth = interactive({ resource: CALENDAR, tokens, flow });
    await authorize(auth);

    await expect(
      auth.getToken({ principal: userPrincipal(), connection }),
    ).rejects.toMatchObject({
      name: "ConnectionAuthorizationFailedError",
      reason: FailureReason.ACQUISITION_FAILED,
      retryable: true,
    });
    // A transient failure keeps the grant for the next attempt.
    expect(await tokens.list(PRINCIPAL_KEY)).toHaveLength(1);
  });

  it("parks on expiry when the grant holds no refresh token", async () => {
    const flow = recordingFlow({
      completion: {
        accessToken: "granted-token",
        tokenType: "Bearer",
        expiresIn: -1,
      },
    });
    const auth = interactive({ resource: CALENDAR, flow });
    await authorize(auth);

    await expect(
      auth.getToken({ principal: userPrincipal(), connection }),
    ).rejects.toMatchObject({
      name: "ConnectionAuthorizationRequiredError",
    });
    expect(flow.refreshes).toEqual([]);
  });

  it("rejects two definitions sharing a connectionName at definition time", () => {
    interactive({
      resource: CALENDAR,
      connectionName: "Calendar",
      flow: recordingFlow(),
    });

    expect(() =>
      interactive({
        resource: "https://other.example.com",
        connectionName: "Calendar",
        flow: recordingFlow(),
      }),
    ).toThrow(AuthProviderConfigurationError);
  });

  it("keeps grants for different resources apart, evict included", async () => {
    const tokens = memoryAuthorizedTokenStore();
    const calendar = interactive({
      resource: CALENDAR,
      connectionName: "Calendar",
      tokens,
      flow: recordingFlow(),
    });
    const docs = interactive({
      resource: "https://docs.example.com",
      connectionName: "Docs",
      tokens,
      flow: recordingFlow({
        completion: {
          accessToken: "docs-token",
          tokenType: "Bearer",
          expiresIn: 900,
        },
      }),
    });
    await authorize(calendar);
    await authorize(docs);

    expect(
      (await calendar.getToken({ principal: userPrincipal(), connection }))
        .token,
    ).toBe("granted-token");
    expect(
      (await docs.getToken({ principal: userPrincipal(), connection })).token,
    ).toBe("docs-token");

    await calendar.evict?.({ principal: userPrincipal(), connection });

    await expect(
      calendar.getToken({ principal: userPrincipal(), connection }),
    ).rejects.toMatchObject({
      name: "ConnectionAuthorizationRequiredError",
    });
    expect(
      (await docs.getToken({ principal: userPrincipal(), connection })).token,
    ).toBe("docs-token");
  });

  it("serves a covered connection from a grant obtained with additionalResources", async () => {
    const tokens = memoryAuthorizedTokenStore();
    const calendar = interactive({
      resource: CALENDAR,
      connectionName: "Calendar",
      additionalResources: ["https://docs.example.com"],
      tokens,
      flow: recordingFlow(),
    });
    const docsFlow = recordingFlow();
    const docs = interactive({
      resource: "https://docs.example.com",
      connectionName: "Docs",
      tokens,
      flow: docsFlow,
    });
    await authorize(calendar);

    const result = await docs.getToken({
      principal: userPrincipal(),
      connection,
    });
    expect(result.token).toBe("granted-token");
    expect(docsFlow.begins).toEqual([]);
  });

  it("does not reuse a grant whose scopes fall short of the connection's", async () => {
    const tokens = memoryAuthorizedTokenStore();
    const reader = interactive({
      resource: CALENDAR,
      connectionName: "Reader",
      tokens,
      flow: recordingFlow(),
    });
    const writer = interactive({
      resource: CALENDAR,
      connectionName: "Writer",
      requestScopes: ["calendar.write"],
      tokens,
      flow: recordingFlow(),
    });
    await authorize(reader);

    await expect(
      writer.getToken({ principal: userPrincipal(), connection }),
    ).rejects.toMatchObject({
      name: "ConnectionAuthorizationRequiredError",
    });
  });
});
