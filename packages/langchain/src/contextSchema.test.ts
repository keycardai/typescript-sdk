import { describe, expect, it } from "@jest/globals";
import { createAgent } from "langchain";
import { tool } from "@langchain/core/tools";
import { z } from "zod";
import { z as z3 } from "zod/v3";
import { Access } from "./access.js";
import { getAccessContext } from "./accessStore.js";
import { keycardIdentitySchema } from "./identity.js";
import { keycardGrantMiddleware } from "./middleware.js";
import { FakeToolCallingModel, recordingZoneClient } from "./testUtils.js";

const CALENDAR = "https://www.googleapis.com/calendar/v3";

/**
 * The middleware declares `keycardIdentitySchema` as its `contextSchema`, and
 * an application declares its own on `createAgent`. LangChain merges the two,
 * so the application's schema can be written with either zod major: the
 * top-level `zod` (4) or the classic `zod/v3` API a zod 3 caller still uses.
 */
async function runWithContextSchema(contextSchema: Parameters<typeof createAgent>[0]["contextSchema"]) {
  const client = recordingZoneClient();
  const observed: { token?: string; tenant?: unknown } = {};

  const readCalendar = tool(
    async (_input, config) => {
      observed.token = getAccessContext().access(CALENDAR).accessToken;
      observed.tenant = (config as { context?: { tenant?: unknown } }).context?.tenant;
      return "ok";
    },
    {
      name: "read_calendar",
      description: "read the calendar",
      schema: z.object({}),
    },
  );

  const agent = createAgent({
    model: new FakeToolCallingModel("read_calendar"),
    tools: [readCalendar],
    contextSchema,
    middleware: [keycardGrantMiddleware({ resources: [CALENDAR], client })],
  });

  await agent.invoke(
    { messages: [{ role: "user", content: "go" }] },
    { context: { tenant: "acme", ...Access.onBehalfOf("caller-token") } },
  );

  return { client, observed };
}

describe("composing keycardIdentitySchema into an agent contextSchema", () => {
  it("works with a zod 4 application schema", async () => {
    const { client, observed } = await runWithContextSchema(
      z.object({ tenant: z.string() }),
    );
    expect(client.exchanges[0]!.subjectToken).toBe("caller-token");
    expect(observed).toEqual({ token: `exchanged:${CALENDAR}`, tenant: "acme" });
  });

  it("works with a zod 3 (zod/v3) application schema", async () => {
    const { client, observed } = await runWithContextSchema(
      z3.object({ tenant: z3.string() }),
    );
    expect(client.exchanges[0]!.subjectToken).toBe("caller-token");
    expect(observed).toEqual({ token: `exchanged:${CALENDAR}`, tenant: "acme" });
  });

  it("extends keycardIdentitySchema directly", async () => {
    const extended = keycardIdentitySchema.extend({ tenant: z.string() });
    const { observed } = await runWithContextSchema(extended);
    expect(observed.tenant).toBe("acme");
    expect(extended.parse({ tenant: "acme", asSelf: true })).toEqual({ tenant: "acme", asSelf: true });
  });
});
