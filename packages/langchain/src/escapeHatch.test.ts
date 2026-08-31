import { describe, expect, it } from "@jest/globals";
import { AuthProviderConfigurationError, OAuthError } from "@keycardai/oauth";
import { tool } from "@langchain/core/tools";
import { z } from "zod";
import { Access } from "./access.js";
import { getAccessContext } from "./accessStore.js";
import { keycardGrantMiddleware } from "./middleware.js";
import { recordingZoneClient } from "./testUtils.js";

const CALENDAR = "https://www.googleapis.com/calendar/v3";
const DOCS = "https://docs.example.com";
const SIGN_IN = "https://zone.example.com/sign-in";
const AUTHORIZE = "https://zone.example.com/authorize";

describe("grant, outside an agent run", () => {
  it("serves getAccessContext to the same tools the agent calls", async () => {
    const keycard = keycardGrantMiddleware({
      resources: [CALENDAR],
      client: recordingZoneClient(),
    });
    const readCalendar = tool(
      async () => getAccessContext().access(CALENDAR).accessToken,
      { name: "read_calendar", description: "read", schema: z.object({}) },
    );

    const token = await keycard.grant(
      { identity: Access.onBehalfOf("caller-token") },
      () => readCalendar.invoke({}),
    );

    expect(token).toBe(`exchanged:${CALENDAR}`);
  });

  it("hands the access context to the callback and returns its value", async () => {
    const keycard = keycardGrantMiddleware({
      resources: [CALENDAR],
      client: recordingZoneClient(),
    });

    const token = await keycard.grant(
      { identity: Access.asSelf() },
      (access) => access.access(CALENDAR).accessToken,
    );

    expect(token).toBe(`as-self:${CALENDAR}`);
  });

  it("grants exactly the resources it is given", async () => {
    const client = recordingZoneClient();
    const keycard = keycardGrantMiddleware({ resources: [CALENDAR], client });

    await keycard.grant(
      { identity: Access.onBehalfOf("caller-token"), resources: [DOCS] },
      () => undefined,
    );

    expect(client.exchanges.map((request) => request.resource)).toEqual([DOCS]);
  });

  it("grants a named tool's resources", async () => {
    const client = recordingZoneClient();
    const keycard = keycardGrantMiddleware({
      resources: [CALENDAR],
      client,
      toolResources: { read_docs: [DOCS] },
    });

    await keycard.grant(
      { identity: Access.onBehalfOf("caller-token"), toolName: "read_docs" },
      () => undefined,
    );

    expect(client.exchanges.map((request) => request.resource)).toEqual([DOCS]);
  });

  it("grants the default resources when given neither", async () => {
    const client = recordingZoneClient();
    const keycard = keycardGrantMiddleware({ resources: [CALENDAR], client });

    await keycard.grant({ identity: Access.onBehalfOf("caller-token") }, () => undefined);

    expect(client.exchanges.map((request) => request.resource)).toEqual([CALENDAR]);
  });

  it("rejects a tool name and a resource list together", async () => {
    const keycard = keycardGrantMiddleware({
      resources: [CALENDAR],
      client: recordingZoneClient(),
    });

    await expect(
      keycard.grant({ toolName: "read_docs", resources: [DOCS] }, () => undefined),
    ).rejects.toThrow(AuthProviderConfigurationError);
  });

  it("falls back to the configured identity when given none", async () => {
    const client = recordingZoneClient();
    const keycard = keycardGrantMiddleware({
      resources: [CALENDAR],
      client,
      fallbackIdentity: Access.onBehalfOf("service-token"),
    });

    await keycard.grant((access) => access.access(CALENDAR));

    expect(client.exchanges[0]!.subjectToken).toBe("service-token");
  });

  it("never interrupts: there is no run to pause, so failures stay on the context", async () => {
    const keycard = keycardGrantMiddleware({
      resources: [CALENDAR, DOCS],
      client: recordingZoneClient({
        [DOCS]: new OAuthError("access_denied", "consent required"),
      }),
      authorizationUrl: AUTHORIZE,
      signInUrl: SIGN_IN,
    });

    const failed = await keycard.grant(
      { identity: Access.onBehalfOf("caller-token") },
      (access) => access.getFailedResources(),
    );

    expect(failed).toEqual([DOCS]);
  });

  it("leaves a missing identity on the context rather than escalating", async () => {
    const client = recordingZoneClient();
    const keycard = keycardGrantMiddleware({ resources: [CALENDAR], client });

    const error = await keycard.grant((access) => access.getError());

    expect(error?.code).toBe("missing_identity");
    expect(client.clientCredentials).toHaveLength(0);
  });

  it("removes the context when the callback returns", async () => {
    const keycard = keycardGrantMiddleware({
      resources: [CALENDAR],
      client: recordingZoneClient(),
    });

    await keycard.grant({ identity: Access.asSelf() }, () => undefined);

    expect(() => getAccessContext()).toThrow(AuthProviderConfigurationError);
  });
});
