import { describe, expect, it } from "@jest/globals";
import { OAuthError } from "@keycardai/oauth";
import { MemorySaver } from "@langchain/langgraph";
import { ToolMessage } from "@langchain/core/messages";
import type { BaseMessage } from "@langchain/core/messages";
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
const SIGN_IN = "https://zone.example.com/sign-in";
const AUTHORIZE = "https://zone.example.com/authorize";

/** The fields a model reads off the fallback tool output. */
interface FallbackFields {
  kind: string;
  reason: string;
  url: string;
}

interface FallbackRun {
  /** The tool output the model received, which stands in for the interrupt. */
  message: ToolMessage;
  /** Interrupt payloads the run raised, which in this mode must be none. */
  interrupts: KeycardInterrupt[];
  /** Tool calls that actually reached the handler. */
  handled: number;
}

/**
 * Run an agent in tool-output mode, deliberately built with no checkpointer:
 * a deployment that keeps no graph state is the case this mode exists for.
 */
async function fallbackRun(
  options: Omit<KeycardGrantMiddlewareOptions, "resources"> & { resources?: string[] },
  identity?: KeycardIdentity,
): Promise<FallbackRun> {
  const state = { handled: 0 };

  const readCalendar = tool(
    async () => {
      state.handled += 1;
      const access = getAccessContext();
      if (access.getFailedResources().length > 0 || access.hasError()) return "failed";
      return `TOKEN:${access.access(CALENDAR).accessToken}`;
    },
    { name: "read_calendar", description: "read", schema: z.object({}) },
  );

  const agent = createAgent({
    model: new FakeToolCallingModel("read_calendar"),
    tools: [readCalendar],
    middleware: [
      keycardGrantMiddleware({
        resources: [CALENDAR],
        interruptOnAuth: false,
        ...options,
      }),
    ],
  });

  const result = (await agent.invoke(
    { messages: [{ role: "user", content: "go" }] },
    identity ? { context: identity } : {},
  )) as { messages: BaseMessage[]; __interrupt__?: { value: KeycardInterrupt }[] };

  const toolMessages = result.messages.filter(
    (message): message is ToolMessage => message instanceof ToolMessage,
  );
  return {
    message: toolMessages[toolMessages.length - 1]!,
    interrupts: (result.__interrupt__ ?? []).map((raised) => raised.value),
    handled: state.handled,
  };
}

/** Read the kind, reason and url back out of the rendered tool output. */
function fallbackFields(message: ToolMessage): FallbackFields {
  const [head, url] = String(message.content).split("\n");
  const [kind, rest] = head!.split(": the tool ");
  return {
    kind: kind!,
    reason: rest!.split("(reason: ")[1]!.replace(/\)\.$/, ""),
    url: url!,
  };
}

const denied = () =>
  recordingZoneClient({
    [CALENDAR]: new OAuthError("access_denied", "consent required"),
  });

describe("sign-in without a checkpointer", () => {
  it("hands the model failed tool output instead of pausing the run", async () => {
    const client = recordingZoneClient();
    const run = await fallbackRun({
      client,
      signInUrl: SIGN_IN,
      authorizationUrl: AUTHORIZE,
    });

    expect(run.interrupts).toHaveLength(0);
    expect(run.message.status).toBe("error");
    expect(fallbackFields(run.message)).toEqual({
      kind: "sign_in_required",
      reason: "missing_identity",
      url: SIGN_IN,
    });
    expect(client.exchanges).toHaveLength(0);
  });

  it("reports an expired subject token with the expiry reason", async () => {
    const client = recordingZoneClient();
    const run = await fallbackRun(
      { client, signInUrl: SIGN_IN, authorizationUrl: AUTHORIZE },
      Access.onBehalfOf(jwtWithExp(Math.floor(Date.now() / 1000) - 60)),
    );

    expect(fallbackFields(run.message)).toEqual({
      kind: "sign_in_required",
      reason: "subject_token_expired",
      url: SIGN_IN,
    });
    expect(client.exchanges).toHaveLength(0);
  });
});

describe("consent without a checkpointer", () => {
  it("hands the model failed tool output instead of pausing the run", async () => {
    const run = await fallbackRun(
      { client: denied(), authorizationUrl: AUTHORIZE },
      Access.onBehalfOf("caller-token"),
    );

    expect(run.interrupts).toHaveLength(0);
    expect(run.message.status).toBe("error");
    expect(fallbackFields(run.message)).toEqual({
      kind: "authorization_required",
      reason: "consent_required",
      url: AUTHORIZE,
    });
  });

  it("resolves a callable authorization URL with the failed resources", async () => {
    const seen: string[][] = [];
    const run = await fallbackRun(
      {
        client: denied(),
        authorizationUrl: (resources) => {
          seen.push(resources);
          return `${AUTHORIZE}?resource=${encodeURIComponent(resources[0]!)}`;
        },
      },
      Access.onBehalfOf("caller-token"),
    );

    expect(seen).toEqual([[CALENDAR]]);
    expect(fallbackFields(run.message).url).toBe(
      `${AUTHORIZE}?resource=${encodeURIComponent(CALENDAR)}`,
    );
  });

  it("records the error on the access context when no URL is configured", async () => {
    const run = await fallbackRun(
      { client: denied() },
      Access.onBehalfOf("caller-token"),
    );

    expect(run.handled).toBe(1);
  });
});

describe("the never-fall-back guarantee", () => {
  it("does not run the wrapped tool, as the interrupt path does not", async () => {
    const run = await fallbackRun(
      { client: denied(), authorizationUrl: AUTHORIZE },
      Access.onBehalfOf("caller-token"),
    );

    expect(run.handled).toBe(0);
    expect(String(run.message.content)).not.toContain("TOKEN:");
  });

  it("never pauses or reports for an as-itself run", async () => {
    const run = await fallbackRun(
      { client: denied(), authorizationUrl: AUTHORIZE, signInUrl: SIGN_IN },
      Access.asSelf(),
    );

    expect(run.handled).toBe(1);
  });
});

describe("the rendered tool output", () => {
  it("stands the URL alone on its own line and demands it verbatim", async () => {
    const run = await fallbackRun(
      { client: denied(), authorizationUrl: AUTHORIZE },
      Access.onBehalfOf("caller-token"),
    );

    const content = String(run.message.content);
    expect(content).toContain(`\n${AUTHORIZE}\n`);
    expect(content).toContain("exactly as written");
    expect(content).toContain("read_calendar");
    expect(run.message.name).toBe("read_calendar");
  });

  /**
   * Byte-for-byte what Python's `interrupt_on_auth=False` renders for the same
   * failure, so a model relaying it behaves the same on either side.
   */
  it("renders what the Python middleware renders", async () => {
    const run = await fallbackRun(
      { client: denied(), authorizationUrl: AUTHORIZE },
      Access.onBehalfOf("caller-token"),
    );

    expect(String(run.message.content)).toBe(
      "authorization_required: the tool read_calendar cannot run yet " +
        "(reason: consent_required).\n" +
        `${AUTHORIZE}\n` +
        "Tell the user to open the URL above to grant this access. Copy it into " +
        "your reply exactly as written, character for character: do not shorten " +
        "it, rewrite it, wrap it in other text, or describe it in words. Then " +
        "ask the user to tell you once they are done, and call read_calendar again.",
    );
  });
});

/**
 * Parity is the contract: the two modes differ in delivery only, so the same
 * failure must reach the user with the same kind, reason and url.
 */
describe("parity with the interrupt payload", () => {
  const cases: {
    name: string;
    kind: KeycardInterrupt["type"];
    identity?: KeycardIdentity;
    deny: boolean;
  }[] = [
    { name: "sign-in", kind: "sign_in_required", deny: false },
    {
      name: "consent",
      kind: "authorization_required",
      identity: Access.onBehalfOf("caller-token"),
      deny: true,
    },
    {
      name: "expired subject token",
      kind: "sign_in_required",
      identity: Access.onBehalfOf(jwtWithExp(Math.floor(Date.now() / 1000) - 60)),
      deny: false,
    },
  ];

  it.each(cases)("carries the $name payload fields", async ({ kind, identity, deny }) => {
    const urls = { signInUrl: SIGN_IN, authorizationUrl: AUTHORIZE };
    const payload = await interruptPayload(urls, identity, deny);
    const run = await fallbackRun(
      { client: deny ? denied() : recordingZoneClient(), ...urls },
      identity,
    );

    expect(payload.type).toBe(kind);
    expect(fallbackFields(run.message)).toEqual({
      kind: payload.type,
      reason:
        payload.type === "sign_in_required" ? payload.reason : "consent_required",
      url:
        payload.type === "sign_in_required"
          ? payload.sign_in_url
          : payload.authorization_url,
    });
  });
});

/** The same failure on the interrupt path, for the parity comparison. */
async function interruptPayload(
  urls: Pick<KeycardGrantMiddlewareOptions, "signInUrl" | "authorizationUrl">,
  identity: KeycardIdentity | undefined,
  deny: boolean,
): Promise<KeycardInterrupt> {
  const readCalendar = tool(async () => "ok", {
    name: "read_calendar",
    description: "read",
    schema: z.object({}),
  });
  const agent = createAgent({
    model: new FakeToolCallingModel("read_calendar"),
    tools: [readCalendar],
    middleware: [
      keycardGrantMiddleware({
        resources: [CALENDAR],
        client: deny ? denied() : recordingZoneClient(),
        ...urls,
      }),
    ],
    checkpointer: new MemorySaver(),
  });

  const result = (await agent.invoke(
    { messages: [{ role: "user", content: "go" }] },
    {
      configurable: { thread_id: `parity-${Math.random()}` },
      ...(identity ? { context: identity } : {}),
    },
  )) as { __interrupt__?: { value: KeycardInterrupt }[] };
  return result.__interrupt__![0]!.value;
}
