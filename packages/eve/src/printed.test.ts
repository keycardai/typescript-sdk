import { beforeEach, describe, expect, it } from "@jest/globals";
import { inspect } from "node:util";
import type { AuthorizationCallback } from "eve/connections";

import { encodeCallbackState } from "./callbackRoute.js";
import { asSelf, impersonate, onBehalfOf } from "./connections.js";
import { interactive, memoryAuthorizedTokenStore, resetInteractiveDefinitions, type WebAppFlow } from "./interactive.js";
import { memorySubjectTokenStore } from "./subjectTokens.js";
import { appPrincipal, connectionContext, fakeZoneClient, userPrincipal, validJwt } from "./testing/testUtils.js";

const ZONE = "https://zone.example.com";
const CALENDAR = "https://calendar.example.com";
const CALLBACK = "https://agent.example.com/connections/calendar/callback";
const connection = connectionContext();

/** The printed form of an object with these fields. */
function printed(name: string, fields: object): string {
  return `${name} ${inspect(fields, { breakLength: Infinity })}`;
}

function check(value: object, want: string, secrets: string[]): void {
  const outputs = [inspect(value, { breakLength: Infinity }), inspect({ nested: value }, { breakLength: Infinity })];
  expect(outputs).toEqual([want, `{ nested: ${want} }`]);
  for (const secret of secrets) {
    expect(secret).toBeTruthy();
    for (const output of outputs) expect(output).not.toContain(secret);
    expect(JSON.stringify(value)).toContain(secret);
  }
}

beforeEach(resetInteractiveDefinitions);

// util.inspect is what console.log uses. A printed token result leaves out
// `token`, and a printed grant leaves out `accessToken` and `refreshToken`.
describe("printed token results leave out the token", () => {
  it.each([
    {
      name: "asSelf",
      getToken: () => asSelf({ resource: CALENDAR, client: fakeZoneClient({ expiresIn: 300 }) }).getToken({ principal: appPrincipal(), connection }),
    },
    {
      name: "impersonate",
      getToken: () =>
        impersonate({ resource: CALENDAR, client: fakeZoneClient({ expiresIn: 300 }), userIdentifier: "ops@example.com" }).getToken({ principal: userPrincipal(), connection }),
    },
    {
      name: "onBehalfOf",
      getToken: () => {
        const subjectTokens = memorySubjectTokenStore();
        subjectTokens.set(`${ZONE}|user-1`, validJwt(3600));
        return onBehalfOf({ resource: CALENDAR, client: fakeZoneClient({ expiresIn: 300 }), subjectTokens }).getToken({
          principal: userPrincipal(),
          connection,
        });
      },
    },
  ])("$name", async ({ getToken }) => {
    const result = await getToken();
    expect(result.expiresAt).toBeGreaterThan(Date.now());
    check(result, printed("TokenResult", { expiresAt: result.expiresAt }), [result.token]);
  });
});

describe("printed interactive grants leave out the tokens", () => {
  it("prints the stored grant and the token result without their tokens", async () => {
    const flow: WebAppFlow = {
      async begin() {
        return { url: `${ZONE}/authorize`, state: "state-1", codeVerifier: "verifier-1", resources: [CALENDAR] };
      },
      async complete() {
        return { accessToken: "granted-token", tokenType: "Bearer", expiresIn: 900, refreshToken: "refresh-token" };
      },
    };
    const tokens = memoryAuthorizedTokenStore();
    const auth = interactive({ resource: CALENDAR, clientId: "web-client", clientSecret: "shh", zoneUrl: ZONE, tokens, flow });
    const started = await auth.startAuthorization({ principal: userPrincipal(), connection, callbackUrl: CALLBACK });
    const callback: AuthorizationCallback = {
      params: { code: "auth-code", state: encodeCallbackState("state-1", CALLBACK) },
      method: "GET",
    };

    const result = await auth.completeAuthorization({
      principal: userPrincipal(),
      connection,
      callbackUrl: CALLBACK,
      resume: started.resume,
      callback,
    });
    const [grant] = await tokens.list(`${ZONE}|user-1`);

    check(result, printed("TokenResult", { expiresAt: result.expiresAt }), ["granted-token"]);
    const { accessToken: _a, refreshToken: _r, ...shown } = grant!;
    check(grant!, printed("AuthorizedGrant", shown), ["granted-token", "refresh-token"]);
  });
});
