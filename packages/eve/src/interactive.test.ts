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
import { interactive, memoryAuthorizedTokenStore, type WebAppFlow } from "./interactive.js";
import { appPrincipal, connectionContext, userPrincipal } from "./testing/testUtils.js";

const CALENDAR = "https://calendar.example.com";
const CALLBACK = "https://agent.example.com/connections/calendar/callback";
const connection = connectionContext();

interface RecordingFlow extends WebAppFlow {
  readonly begins: BeginAuthorizationOptions[];
  readonly completes: CompleteAuthorizationOptions[];
}

function recordingFlow(options: { completion?: Error | TokenResponse } = {}): RecordingFlow {
  const begins: BeginAuthorizationOptions[] = [];
  const completes: CompleteAuthorizationOptions[] = [];
  return {
    begins,
    completes,
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
  };
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
    });
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

  it("requires a zone URL and client ID unless a flow is injected", () => {
    expect(() => interactive({ resource: CALENDAR })).toThrow(AuthProviderConfigurationError);
    expect(() => interactive({ resource: "", flow: recordingFlow() })).toThrow(
      AuthProviderConfigurationError,
    );
  });
});
