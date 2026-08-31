import { describe, expect, it } from "@jest/globals";
import { AccessContext, ResourceAccessError } from "@keycardai/oauth";
import { tool } from "@langchain/core/tools";
import { z } from "zod";
import { getAccessContext } from "../accessStore.js";
import { mockAccessContext, overrideAccessContext } from "./testUtils.js";

const CALENDAR = "https://www.googleapis.com/calendar/v3";
const DOCS = "https://docs.example.com";

const readCalendar = tool(
  async () => getAccessContext().access(CALENDAR).accessToken,
  { name: "read_calendar", description: "read", schema: z.object({}) },
);

describe("mockAccessContext", () => {
  it("serves per-resource tokens with no zone and no network", async () => {
    const token = await mockAccessContext(
      { resourceTokens: { [CALENDAR]: "test-token" } },
      () => readCalendar.invoke({}),
    );

    expect(token).toBe("test-token");
  });

  it("catches a tool reading a resource the middleware was never asked to grant", async () => {
    await expect(
      mockAccessContext({ resourceTokens: { [DOCS]: "test-token" } }, () =>
        readCalendar.invoke({}),
      ),
    ).rejects.toThrow(ResourceAccessError);
  });

  it("serves one token for any resource when that is enough", async () => {
    const token = await mockAccessContext({ accessToken: "any-token" }, () =>
      readCalendar.invoke({}),
    );

    expect(token).toBe("any-token");
  });

  it("simulates a per-resource failure", async () => {
    await mockAccessContext(
      {
        resourceTokens: { [CALENDAR]: "test-token" },
        resourceErrors: { [DOCS]: "consent required" },
      },
      (access) => {
        expect(access.access(CALENDAR).accessToken).toBe("test-token");
        expect(access.getFailedResources()).toEqual([DOCS]);
        expect(access.getResourceError(DOCS)?.message).toBe("consent required");
        expect(access.hasError()).toBe(false);
      },
    );
  });

  it("simulates a global failure, serving no resource tokens", async () => {
    await mockAccessContext(
      { accessToken: "any-token", errorMessage: "zone unreachable" },
      (access) => {
        expect(access.getError()?.message).toBe("zone unreachable");
        expect(() => access.access(CALENDAR)).toThrow(ResourceAccessError);
      },
    );
  });

  it("removes the context when the callback returns", async () => {
    await mockAccessContext({ accessToken: "any-token" }, () => undefined);

    expect(() => getAccessContext()).toThrow(/middleware/);
  });
});

describe("overrideAccessContext", () => {
  it("serves a hand-built access context, partial failures included", async () => {
    const access = new AccessContext();
    access.setToken(CALENDAR, { accessToken: "hand-built", tokenType: "Bearer" });
    access.setResourceError(DOCS, { message: "consent required", code: "access_denied" });

    const token = await overrideAccessContext(access, () => readCalendar.invoke({}));

    expect(token).toBe("hand-built");
    expect(access.getFailedResources()).toEqual([DOCS]);
  });
});
