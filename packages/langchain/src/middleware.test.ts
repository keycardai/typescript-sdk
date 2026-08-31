import { describe, expect, it } from "@jest/globals";
import {
  AuthProviderConfigurationError,
  ClientSecret,
  OAuthError,
  ResourceAccessError,
  type ApplicationCredential,
  type TokenExchangeRequest,
} from "@keycardai/oauth";
import { createAgent } from "langchain";
import { tool } from "@langchain/core/tools";
import { z } from "zod";
import { Access } from "./access.js";
import { getAccessContext } from "./accessStore.js";
import {
  keycardGrantMiddleware,
  type KeycardGrantMiddlewareOptions,
} from "./middleware.js";
import type { KeycardIdentity } from "./identity.js";
import { FakeToolCallingModel, jwtWithExp, recordingZoneClient } from "./testUtils.js";

const CALENDAR = "https://www.googleapis.com/calendar/v3";
const DOCS = "https://docs.example.com";

/**
 * Run one tool call through a real agent loop.
 *
 * The tool reports what it saw of the access context, so assertions read the
 * tool's view rather than the middleware's internals.
 */
async function runToolCall(
  options: Omit<KeycardGrantMiddlewareOptions, "resources"> & { resources?: string[] },
  identity?: KeycardIdentity,
  toolName = "read_calendar",
) {
  const observed: {
    tokens: Record<string, string>;
    error: string | null;
    errorCode?: string;
    failed: string[];
    thrown?: unknown;
  } = { tokens: {}, error: null, failed: [] };

  const readCalendar = tool(
    async ({ resources }: { resources?: string[] }) => {
      const access = getAccessContext();
      observed.error = access.getError()?.message ?? null;
      observed.errorCode = access.getError()?.code;
      observed.failed = access.getFailedResources();
      for (const resource of resources ?? access.getSuccessfulResources()) {
        try {
          observed.tokens[resource] = access.access(resource).accessToken;
        } catch (e) {
          observed.thrown = e;
        }
      }
      return "ok";
    },
    {
      name: toolName,
      description: "read the calendar",
      schema: z.object({ resources: z.array(z.string()).optional() }),
    },
  );

  const agent = createAgent({
    model: new FakeToolCallingModel(toolName),
    tools: [readCalendar],
    middleware: [keycardGrantMiddleware({ resources: [CALENDAR], ...options })],
  });

  await agent.invoke(
    { messages: [{ role: "user", content: "go" }] },
    identity ? { context: identity } : {},
  );

  return observed;
}

describe("acquisition", () => {
  it("exchanges the caller's token for each configured resource", async () => {
    const client = recordingZoneClient();
    const observed = await runToolCall(
      { client, resources: [CALENDAR, DOCS] },
      Access.onBehalfOf("caller-token"),
    );

    expect(client.exchanges.map((request) => request.resource)).toEqual([
      CALENDAR,
      DOCS,
    ]);
    expect(client.exchanges[0]!.subjectToken).toBe("caller-token");
    expect(observed.tokens).toEqual({
      [CALENDAR]: `exchanged:${CALENDAR}`,
      [DOCS]: `exchanged:${DOCS}`,
    });
  });

  it("uses the substitute-user exchange for impersonation", async () => {
    const client = recordingZoneClient();
    const observed = await runToolCall({ client }, Access.impersonate("user@example.com"));

    expect(client.impersonations).toEqual([
      { userIdentifier: "user@example.com", resource: CALENDAR },
    ]);
    expect(client.exchanges).toHaveLength(0);
    expect(observed.tokens[CALENDAR]).toBe(`impersonated:${CALENDAR}`);
  });

  it("uses the client-credentials grant for the agent's own authority", async () => {
    const client = recordingZoneClient();
    const observed = await runToolCall({ client }, Access.asSelf());

    expect(client.clientCredentials).toEqual([{ resource: CALENDAR }]);
    expect(client.exchanges).toHaveLength(0);
    expect(client.impersonations).toHaveLength(0);
    expect(observed.tokens[CALENDAR]).toBe(`as-self:${CALENDAR}`);
  });

  it("acquires each resource independently, so one denial spares the rest", async () => {
    const client = recordingZoneClient({
      [DOCS]: new OAuthError("access_denied", "consent required"),
    });
    const observed = await runToolCall(
      { client, resources: [CALENDAR, DOCS] },
      Access.onBehalfOf("caller-token"),
    );

    expect(observed.tokens).toEqual({ [CALENDAR]: `exchanged:${CALENDAR}` });
    expect(observed.failed).toEqual([DOCS]);
    expect(observed.error).toBeNull();
  });

  it("records the failure code from the zone", async () => {
    const client = recordingZoneClient({
      [CALENDAR]: new OAuthError("access_denied", "consent required"),
    });
    let error: unknown;
    const readCalendar = tool(
      async () => {
        error = getAccessContext().getResourceError(CALENDAR);
        return "ok";
      },
      { name: "read_calendar", description: "read", schema: z.object({}) },
    );
    const agent = createAgent({
      model: new FakeToolCallingModel("read_calendar"),
      tools: [readCalendar],
      middleware: [keycardGrantMiddleware({ resources: [CALENDAR], client })],
    });
    await agent.invoke(
      { messages: [{ role: "user", content: "go" }] },
      { context: Access.onBehalfOf("caller-token") },
    );

    expect(error).toEqual({
      message: `Token exchange failed for ${CALENDAR}`,
      code: "access_denied",
      description: expect.stringContaining("consent required"),
    });
  });
});

describe("identity resolution", () => {
  it("records missing_identity and never falls back to the agent's authority", async () => {
    const client = recordingZoneClient();
    const observed = await runToolCall({ client });

    expect(observed.errorCode).toBe("missing_identity");
    expect(client.exchanges).toHaveLength(0);
    expect(client.impersonations).toHaveLength(0);
    expect(client.clientCredentials).toHaveLength(0);
  });

  it("uses a fallback identity when the run carries none", async () => {
    const client = recordingZoneClient();
    const observed = await runToolCall({
      client,
      fallbackIdentity: Access.onBehalfOf("service-token"),
    });

    expect(client.exchanges[0]!.subjectToken).toBe("service-token");
    expect(observed.error).toBeNull();
  });

  it("resolves a callable fallback per tool call", async () => {
    const client = recordingZoneClient();
    let current = "first-token";
    await runToolCall({
      client,
      fallbackIdentity: () => Access.onBehalfOf(current),
    });
    current = "second-token";
    await runToolCall({ client, fallbackIdentity: () => Access.onBehalfOf(current) });

    expect(client.exchanges.map((request) => request.subjectToken)).toEqual([
      "first-token",
      "second-token",
    ]);
  });

  it("prefers the run's identity over the fallback", async () => {
    const client = recordingZoneClient();
    await runToolCall(
      { client, fallbackIdentity: Access.onBehalfOf("service-token") },
      Access.onBehalfOf("caller-token"),
    );

    expect(client.exchanges[0]!.subjectToken).toBe("caller-token");
  });
});

describe("resource selection", () => {
  it("gives a tool absent from toolResources the default resources", async () => {
    const client = recordingZoneClient();
    await runToolCall(
      { client, resources: [CALENDAR], toolResources: { other_tool: [DOCS] } },
      Access.onBehalfOf("caller-token"),
    );

    expect(client.exchanges.map((request) => request.resource)).toEqual([CALENDAR]);
  });

  it("gives a tool in toolResources exactly its override", async () => {
    const client = recordingZoneClient();
    await runToolCall(
      { client, resources: [CALENDAR], toolResources: { read_calendar: [DOCS] } },
      Access.onBehalfOf("caller-token"),
    );

    expect(client.exchanges.map((request) => request.resource)).toEqual([DOCS]);
  });

  it("exchanges nothing for a tool whose override is empty", async () => {
    const client = recordingZoneClient();
    const observed = await runToolCall(
      { client, resources: [CALENDAR], toolResources: { read_calendar: [] } },
      Access.onBehalfOf("caller-token"),
    );

    expect(client.exchanges).toHaveLength(0);
    expect(observed.error).toBeNull();
    expect(observed.failed).toHaveLength(0);
  });
});

describe("requested scopes", () => {
  it("sends a global scope list on the exchange", async () => {
    const client = recordingZoneClient();
    await runToolCall(
      { client, requestScopes: ["calendar.read", "calendar.write"] },
      Access.onBehalfOf("caller-token"),
    );

    expect(client.exchanges[0]!.scope).toBe("calendar.read calendar.write");
  });

  it("sends per-resource scopes", async () => {
    const client = recordingZoneClient();
    await runToolCall(
      {
        client,
        resources: [CALENDAR, DOCS],
        requestScopes: { [CALENDAR]: "calendar.read" },
      },
      Access.onBehalfOf("caller-token"),
    );

    expect(client.exchanges.map((request) => request.scope)).toEqual([
      "calendar.read",
      undefined,
    ]);
  });

  it("sends the scope on the client-credentials grant too", async () => {
    const client = recordingZoneClient();
    await runToolCall({ client, requestScopes: "calendar.read" }, Access.asSelf());

    expect(client.clientCredentials[0]!.scope).toBe("calendar.read");
  });
});

describe("expired subject tokens", () => {
  it("routes an expired token to sign-in, not consent, without asking the zone", async () => {
    const client = recordingZoneClient();
    const observed = await runToolCall(
      { client },
      Access.onBehalfOf(jwtWithExp(Math.floor(Date.now() / 1000) - 60)),
    );

    expect(observed.errorCode).toBe("subject_token_expired");
    expect(client.exchanges).toHaveLength(0);
  });

  it("sends an unexpired token to the zone", async () => {
    const client = recordingZoneClient();
    const token = jwtWithExp(Math.floor(Date.now() / 1000) + 3600);
    const observed = await runToolCall({ client }, Access.onBehalfOf(token));

    expect(client.exchanges[0]!.subjectToken).toBe(token);
    expect(observed.error).toBeNull();
  });
});

describe("configuration", () => {
  it("requires a zone URL", () => {
    expect(() => keycardGrantMiddleware({ resources: [CALENDAR] })).toThrow(
      AuthProviderConfigurationError,
    );
    expect(() => keycardGrantMiddleware({ resources: [CALENDAR] })).toThrow(/zoneUrl/);
  });

  it("rejects two credential paths at once", () => {
    expect(() =>
      keycardGrantMiddleware({
        zoneUrl: "https://zone.example.com",
        resources: [CALENDAR],
        applicationCredential: new ClientSecret("id", "secret"),
        clientId: "id",
        clientSecret: "secret",
      }),
    ).toThrow(AuthProviderConfigurationError);
  });

  it("accepts clientId/clientSecret as a ClientSecret shorthand", async () => {
    const client = recordingZoneClient();
    const observed = await runToolCall(
      { client, clientId: "agent", clientSecret: "shh" },
      Access.onBehalfOf("caller-token"),
    );

    expect(observed.error).toBeNull();
    expect(client.exchanges[0]!.clientAssertion).toBeUndefined();
  });

  it("carries an assertion credential's proof into the exchange", async () => {
    const client = recordingZoneClient();
    await runToolCall(
      { client, applicationCredential: assertionCredential() },
      Access.onBehalfOf("caller-token"),
    );

    expect(client.exchanges[0]).toEqual({
      subjectToken: "caller-token",
      resource: CALENDAR,
      clientAssertion: `assertion:${CALENDAR}`,
      clientAssertionType: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    });
  });

  it("carries an assertion credential's proof into the client-credentials grant", async () => {
    const client = recordingZoneClient();
    await runToolCall(
      { client, applicationCredential: assertionCredential() },
      Access.asSelf(),
    );

    expect(client.clientCredentials[0]).toEqual({
      resource: CALENDAR,
      clientAssertion: `assertion:${CALENDAR}`,
      clientAssertionType: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    });
  });
});

describe("tool schema", () => {
  it("keeps auth out of the model-facing schema", async () => {
    const readCalendar = tool(async () => "ok", {
      name: "read_calendar",
      description: "read the calendar",
      schema: z.object({ daysAhead: z.number() }),
    });

    const agent = createAgent({
      model: new FakeToolCallingModel("read_calendar"),
      tools: [readCalendar],
      middleware: [
        keycardGrantMiddleware({ resources: [CALENDAR], client: recordingZoneClient() }),
      ],
    });
    await agent.invoke(
      { messages: [{ role: "user", content: "go" }] },
      { context: Access.onBehalfOf("caller-token") },
    );

    const shape = (readCalendar.schema as z.ZodObject<{ daysAhead: z.ZodNumber }>).shape;

    expect(Object.keys(shape)).toEqual(["daysAhead"]);
  });
});

describe("access context lifetime", () => {
  it("is installed only around the tool call", async () => {
    const client = recordingZoneClient();
    await runToolCall({ client }, Access.onBehalfOf("caller-token"));

    expect(() => getAccessContext()).toThrow(AuthProviderConfigurationError);
  });

  it("reports the missing middleware when a tool runs without it", () => {
    expect(() => getAccessContext()).toThrow(/middleware/);
  });

  it("raises ResourceAccessError only when a tool reads an ungranted resource", async () => {
    expect(await runToolCallReading(CALENDAR)).toBeUndefined();
    expect(await runToolCallReading(DOCS)).toBeInstanceOf(ResourceAccessError);
  });
});

/** Run a tool that reads `resource`, and report what reading it threw. */
async function runToolCallReading(resource: string): Promise<unknown> {
  let thrown: unknown;
  const readCalendar = tool(
    async () => {
      try {
        getAccessContext().access(resource);
      } catch (e) {
        thrown = e;
      }
      return "ok";
    },
    { name: "read_calendar", description: "read", schema: z.object({}) },
  );
  const agent = createAgent({
    model: new FakeToolCallingModel("read_calendar"),
    tools: [readCalendar],
    middleware: [
      keycardGrantMiddleware({ resources: [CALENDAR], client: recordingZoneClient() }),
    ],
  });
  await agent.invoke(
    { messages: [{ role: "user", content: "go" }] },
    { context: Access.onBehalfOf("caller-token") },
  );
  return thrown;
}

/**
 * A credential whose proof rides in the request body rather than the
 * Authorization header, as file- and platform-backed credentials do.
 */
function assertionCredential(): ApplicationCredential {
  return {
    getAuth: () => null,
    async prepareTokenExchangeRequest(
      subjectToken: string,
      resource: string,
    ): Promise<TokenExchangeRequest> {
      return {
        subjectToken,
        resource,
        clientAssertion: `assertion:${resource}`,
        clientAssertionType:
          "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      };
    },
  };
}
