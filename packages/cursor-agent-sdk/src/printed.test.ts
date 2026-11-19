import { describe, expect, it } from "@jest/globals";
import { inspect } from "node:util";

import { asSelf, impersonate, onBehalfOf } from "./connections.js";
import { memorySubjectTokenStore } from "./subjectTokens.js";
import { fakeZoneClient, keycardPrincipal, session, validJwt } from "./testing/testUtils.js";

const ZONE = "https://zone.example.com";
const CALENDAR = "https://calendar.example.com";
const WANT = "ConnectionAuthResult { headers: [ 'authorization' ] }";

// Each connection auth returns headers with a bearer token. util.inspect is
// what console.log uses, and it prints the header names only.
describe("printed connection auth results leave out the bearer token", () => {
  it.each([
    { name: "impersonate", auth: () => impersonate({ resource: CALENDAR, zoneUrl: ZONE, client: fakeZoneClient() }) },
    { name: "asSelf", auth: () => asSelf({ resource: CALENDAR, client: fakeZoneClient() }) },
    {
      name: "onBehalfOf",
      auth: () => {
        const subjectTokens = memorySubjectTokenStore();
        subjectTokens.set(`${ZONE}|user-1`, validJwt(3600));
        return onBehalfOf({ resource: CALENDAR, zoneUrl: ZONE, client: fakeZoneClient(), subjectTokens });
      },
    },
  ])("$name", async ({ auth }) => {
    const result = await auth()(session(keycardPrincipal()));
    const header = result.headers.authorization;
    const outputs = [inspect(result, { breakLength: Infinity }), inspect({ nested: result }, { breakLength: Infinity })];

    expect(header).toMatch(/^Bearer \S+/);
    expect(outputs).toEqual([WANT, `{ nested: ${WANT} }`]);
    for (const output of outputs) expect(output).not.toContain(header.slice("Bearer ".length));
    expect(JSON.stringify(result)).toContain(header);
  });
});
