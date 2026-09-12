import { describe, expect, it } from "@jest/globals";
import {
  AuthProviderConfigurationError,
  AuthorizationDeniedError,
  StateMismatchError,
  type AuthorizationRedirect,
  type BeginAuthorizationOptions,
  type CompleteAuthorizationOptions,
  type TokenResponse,
} from "@keycardai/oauth";
import type { AuthorizationCallback } from "eve/connections";

import { FailureReason } from "./errors.js";
import {
  interactive,
  memoryAuthorizedTokenStore,
  type RegisterAttemptClientOptions,
  type RegisteredClient,
  type WebAppFlow,
} from "./interactive.js";
import { appPrincipal, connectionContext, userPrincipal } from "./testing/testUtils.js";

const CALENDAR = "https://calendar.example.com";
const CALLBACK = "https://agent.example.com/connections/calendar/callback";
const connection = connectionContext();

interface RecordingFlow extends WebAppFlow {
  readonly begins: BeginAuthorizationOptions[];
  readonly completes: CompleteAuthorizationOptions[];
  readonly registrations: RegisterAttemptClientOptions[];
}

function recordingFlow(
  options: {
    completion?: Error | TokenResponse;
    registration?: Error | RegisteredClient;
  } = {},
): RecordingFlow {
  const begins: BeginAuthorizationOptions[] = [];
  const completes: CompleteAuthorizationOptions[] = [];
  const registrations: RegisterAttemptClientOptions[] = [];
  return {
    begins,
    completes,
    registrations,
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
      return completion ?? { accessToken: "granted-token", tokenType: "Bearer", expiresIn: 900 };
    },
    async register(registerOptions): Promise<RegisteredClient> {
      registrations.push(registerOptions);
      const registration = options.registration;
      if (registration instanceof Error) throw registration;
      // A different client per attempt, so a test can tell which one redeemed.
      return registration ?? { clientId: `attempt-client-${registrations.length}` };
    },
  };
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

    await expect(auth.getToken({ principal: userPrincipal(), connection })).rejects.toMatchObject({
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

    // eve validates an authored connection's `auth` against this closed list.
    // A key outside it — `displayName` is the one this package used to set —
    // fails the build for every connection using it.
    const allowed = [
      "completeAuthorization",
      "evict",
      "getToken",
      "principalType",
      "startAuthorization",
      "vercelConnect",
    ];
    expect(Object.keys(auth).filter((key) => !allowed.includes(key))).toEqual([]);

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
    expect(started.challenge.url).toContain("https://zone.example.com/authorize");
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
    const reused = await auth.getToken({ principal: userPrincipal(), connection });
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
    await expect(auth.getToken({ principal: userPrincipal(), connection })).rejects.toMatchObject({
      name: "ConnectionAuthorizationRequiredError",
    });
    expect(flow.completes).toEqual([]);
  });

  it("keeps a denied authorization from yielding a token", async () => {
    const flow = recordingFlow({
      completion: new AuthorizationDeniedError("access_denied", "User denied the request"),
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

    await expect(auth.getToken({ principal: userPrincipal(), connection })).rejects.toMatchObject({
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
    ).rejects.toMatchObject({ reason: FailureReason.INVALID_CALLBACK, retryable: false });
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

    auth.evict?.({ principal: userPrincipal(), connection });

    await expect(auth.getToken({ principal: userPrincipal(), connection })).rejects.toMatchObject({
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
    expect(() => interactive({ resource: CALENDAR })).toThrow(AuthProviderConfigurationError);
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
    expect(() => interactive({ resource: CALENDAR, flow: staticOnlyFlow() })).toThrow(
      AuthProviderConfigurationError,
    );
    // The same flow is fine once a client is configured.
    expect(() =>
      interactive({ resource: CALENDAR, clientId: "web-client", flow: staticOnlyFlow() }),
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
      { redirectUri: CALLBACK, clientName: "Calendar", scopes: ["calendar.read"] },
    ]);
    // The authorization request runs as the client just registered for it.
    expect(flow.begins[0]?.clientId).toBe("attempt-client-1");
    expect(started.resume.clientId).toBe("attempt-client-1");
  });

  it("gives each attempt its own client and callback", async () => {
    const flow = recordingFlow();
    const auth = interactive({ resource: CALENDAR, zoneUrl: "https://zone.example.com", flow });
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

    expect(flow.registrations.map((entry) => entry.redirectUri)).toEqual([CALLBACK, second]);
    expect(flow.begins.map((entry) => entry.clientId)).toEqual([
      "attempt-client-1",
      "attempt-client-2",
    ]);
  });

  it("redeems the code as the client that made the request", async () => {
    const flow = recordingFlow();
    const auth = interactive({ resource: CALENDAR, zoneUrl: "https://zone.example.com", flow });
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
    const auth = interactive({ resource: CALENDAR, zoneUrl: "https://zone.example.com", flow });

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
      registration: { clientId: "attempt-client-1", clientSecret: "issued-secret" },
    });
    const auth = interactive({ resource: CALENDAR, zoneUrl: "https://zone.example.com", flow });

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
    const flow = recordingFlow({ registration: new Error("registration endpoint returned 503") });
    const auth = interactive({ resource: CALENDAR, zoneUrl: "https://zone.example.com", flow });

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
