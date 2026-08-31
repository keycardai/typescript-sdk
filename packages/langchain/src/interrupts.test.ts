import { describe, expect, it } from "@jest/globals";
import { OAuthError } from "@keycardai/oauth";
import { Command, MemorySaver } from "@langchain/langgraph";
import { tool } from "@langchain/core/tools";
import { createAgent } from "langchain";
import { z } from "zod";
import { Access } from "./access.js";
import { getAccessContext } from "./accessStore.js";
import {
  keycardGrantMiddleware,
  type KeycardGrantMiddlewareOptions,
  type KeycardInterrupt,
} from "./middleware.js";
import type { KeycardIdentity } from "./identity.js";
import { FakeToolCallingModel, jwtWithExp, recordingZoneClient } from "./testUtils.js";

const CALENDAR = "https://www.googleapis.com/calendar/v3";
const DOCS = "https://docs.example.com";
const SIGN_IN = "https://zone.example.com/sign-in";
const AUTHORIZE = "https://zone.example.com/authorize";

interface Run {
  /** Interrupt payloads the run has raised so far, in order. */
  interrupts: KeycardInterrupt[];
  /** Tool calls that actually reached the handler. */
  handled: number;
  /** Resume the run, as a user returning from the sign-in or consent page. */
  resume(): Promise<Run>;
}

/**
 * Start an interruptible agent run.
 *
 * A checkpointer plus a thread id is what makes `interrupt()` resumable, so
 * these tests wire both, exactly as a deployment would.
 */
function interruptibleRun(
  options: Omit<KeycardGrantMiddlewareOptions, "resources"> & { resources?: string[] },
  identity?: KeycardIdentity,
): Promise<Run> {
  const state = { interrupts: [] as KeycardInterrupt[], handled: 0 };

  const readCalendar = tool(
    async () => {
      state.handled += 1;
      getAccessContext();
      return "ok";
    },
    { name: "read_calendar", description: "read", schema: z.object({}) },
  );

  const agent = createAgent({
    model: new FakeToolCallingModel("read_calendar"),
    tools: [readCalendar],
    middleware: [keycardGrantMiddleware({ resources: [CALENDAR], ...options })],
    checkpointer: new MemorySaver(),
  });
  const config = { configurable: { thread_id: "thread-1" } };

  const advance = async (
    input: Parameters<typeof agent.invoke>[0],
  ): Promise<Run> => {
    const result = (await agent.invoke(input, {
      ...config,
      ...(identity ? { context: identity } : {}),
    })) as { __interrupt__?: { value: KeycardInterrupt }[] };
    for (const raised of result.__interrupt__ ?? []) {
      state.interrupts.push(raised.value);
    }
    return {
      get interrupts() {
        return state.interrupts;
      },
      get handled() {
        return state.handled;
      },
      resume: () => advance(new Command({ resume: "resumed" }) as never),
    };
  };

  return advance({ messages: [{ role: "user", content: "go" }] });
}

describe("sign-in interrupts", () => {
  it("pauses a run that carries no identity", async () => {
    const run = await interruptibleRun({ client: recordingZoneClient(), signInUrl: SIGN_IN });

    expect(run.interrupts).toEqual([
      {
        type: "sign_in_required",
        sign_in_url: SIGN_IN,
        reason: "missing_identity",
        message: expect.any(String),
      },
    ]);
    expect(run.handled).toBe(0);
  });

  it("distinguishes an expired subject token from a missing identity", async () => {
    const run = await interruptibleRun(
      { client: recordingZoneClient(), signInUrl: SIGN_IN },
      Access.onBehalfOf(jwtWithExp(Math.floor(Date.now() / 1000) - 60)),
    );

    expect(run.interrupts[0]).toMatchObject({
      type: "sign_in_required",
      sign_in_url: SIGN_IN,
      reason: "subject_token_expired",
    });
  });

  it("records an error instead of pausing when no sign-in URL is configured", async () => {
    const run = await interruptibleRun({ client: recordingZoneClient() });

    expect(run.interrupts).toHaveLength(0);
    expect(run.handled).toBe(1);
  });

  it("picks up an identity established during the pause", async () => {
    const client = recordingZoneClient();
    let signedIn: KeycardIdentity | null = null;
    const run = await interruptibleRun({
      client,
      signInUrl: SIGN_IN,
      fallbackIdentity: () => signedIn,
    });
    expect(run.interrupts).toHaveLength(1);

    signedIn = Access.onBehalfOf("token-from-sign-in");
    const resumed = await run.resume();

    expect(resumed.interrupts).toHaveLength(1);
    expect(resumed.handled).toBe(1);
    expect(client.exchanges[0]!.subjectToken).toBe("token-from-sign-in");
  });
});

describe("authorization interrupts", () => {
  const denied = () =>
    recordingZoneClient({
      [DOCS]: new OAuthError("access_denied", "consent required"),
    });

  it("pauses on an ungranted resource, naming only the failed ones", async () => {
    const run = await interruptibleRun(
      { client: denied(), resources: [CALENDAR, DOCS], authorizationUrl: AUTHORIZE },
      Access.onBehalfOf("caller-token"),
    );

    expect(run.interrupts).toEqual([
      {
        type: "authorization_required",
        authorization_url: AUTHORIZE,
        resources: [DOCS],
        errors: {
          [DOCS]: {
            message: `Token exchange failed for ${DOCS}`,
            code: "access_denied",
            description: expect.any(String),
          },
        },
        message: expect.any(String),
      },
    ]);
    expect(run.handled).toBe(0);
  });

  it("resolves a callable authorization URL with the failed resources", async () => {
    const seen: string[][] = [];
    const run = await interruptibleRun(
      {
        client: denied(),
        resources: [CALENDAR, DOCS],
        authorizationUrl: (resources) => {
          seen.push(resources);
          return `${AUTHORIZE}?resource=${encodeURIComponent(resources[0]!)}`;
        },
      },
      Access.onBehalfOf("caller-token"),
    );

    expect(seen).toEqual([[DOCS]]);
    expect(run.interrupts[0]).toMatchObject({
      authorization_url: `${AUTHORIZE}?resource=${encodeURIComponent(DOCS)}`,
    });
  });

  it("records the error instead of pausing when no authorization URL is configured", async () => {
    const run = await interruptibleRun(
      { client: denied(), resources: [CALENDAR, DOCS] },
      Access.onBehalfOf("caller-token"),
    );

    expect(run.interrupts).toHaveLength(0);
    expect(run.handled).toBe(1);
  });

  it("retries acquisition on resume and proceeds once access is granted", async () => {
    const failures: Record<string, Error> = {
      [DOCS]: new OAuthError("access_denied", "consent required"),
    };
    const client = recordingZoneClient(failures);
    const run = await interruptibleRun(
      { client, resources: [CALENDAR, DOCS], authorizationUrl: AUTHORIZE },
      Access.onBehalfOf("caller-token"),
    );
    expect(run.interrupts).toHaveLength(1);

    delete failures[DOCS];
    const resumed = await run.resume();

    expect(resumed.interrupts).toHaveLength(1);
    expect(resumed.handled).toBe(1);
  });

  it("re-interrupts a premature resume rather than calling the tool unauthorized", async () => {
    const run = await interruptibleRun(
      { client: denied(), resources: [CALENDAR, DOCS], authorizationUrl: AUTHORIZE },
      Access.onBehalfOf("caller-token"),
    );

    const resumed = await run.resume();

    expect(resumed.interrupts).toHaveLength(2);
    expect(resumed.handled).toBe(0);
  });

  it("bounds the loop at three attempts, then leaves the failure to the tool", async () => {
    let run = await interruptibleRun(
      { client: denied(), resources: [CALENDAR, DOCS], authorizationUrl: AUTHORIZE },
      Access.onBehalfOf("caller-token"),
    );
    run = await run.resume();
    run = await run.resume();

    expect(run.interrupts).toHaveLength(3);
    expect(run.handled).toBe(0);

    run = await run.resume();

    expect(run.interrupts).toHaveLength(3);
    expect(run.handled).toBe(1);
  });
});

describe("the agent's own authority", () => {
  it("never pauses, even with both URLs configured", async () => {
    const run = await interruptibleRun(
      {
        client: recordingZoneClient({
          [CALENDAR]: new OAuthError("access_denied", "not entitled"),
        }),
        authorizationUrl: AUTHORIZE,
        signInUrl: SIGN_IN,
      },
      Access.asSelf(),
    );

    expect(run.interrupts).toHaveLength(0);
    expect(run.handled).toBe(1);
  });
});
