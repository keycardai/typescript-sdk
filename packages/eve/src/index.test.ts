import { describe, expect, it } from "@jest/globals";

import { Keycard, keycardAuth, requireAuthOnUnauthorized } from "./index.js";
import { connectionContext, fakeZoneClient, userPrincipal, validJwt } from "./testing/testUtils.js";
import { memorySubjectTokenStore } from "./subjectTokens.js";

const CALENDAR = "https://calendar.example.com";
const ZONE = "https://zone.example.com";
const connection = connectionContext();

describe("package surface", () => {
  it("exposes every adapter from the one dependency", () => {
    expect(typeof keycardAuth).toBe("function");
    expect(Object.keys(Keycard).sort()).toEqual([
      "asSelf",
      "impersonate",
      "interactive",
      "onBehalfOf",
    ]);
  });

  it("carries no auth arguments into the connection's own surface", async () => {
    const store = memorySubjectTokenStore();
    store.set(`${ZONE}|user-1`, validJwt(3600));
    const auth = Keycard.onBehalfOf({
      resource: CALENDAR,
      client: fakeZoneClient(),
      subjectTokens: store,
    });

    // A connection's model-facing schema comes from the server's tool list;
    // the auth definition contributes callbacks and metadata only, so no
    // credential and no auth argument can reach the model through it.
    expect(Object.keys(auth).sort()).toEqual(["displayName", "getToken", "principalType"]);

    const result = await auth.getToken({ principal: userPrincipal(), connection });

    // The token is returned to the runtime, which attaches it as a header. It
    // is never stored on the definition, so nothing token-shaped survives here
    // for a serializer to sweep into conversation history.
    expect(JSON.stringify(auth)).not.toContain(result.token);
    expect(JSON.stringify(auth)).toBe(`{"principalType":"user","displayName":"${CALENDAR}"}`);
  });
});

describe("requireAuthOnUnauthorized", () => {
  it("maps a provider 401 to ctx.requireAuth", () => {
    const auth = Keycard.asSelf({ resource: CALENDAR, client: fakeZoneClient() });
    const seen: unknown[] = [];
    const ctx = {
      requireAuth(provider: unknown, options?: { readonly reason?: string }): never {
        seen.push({ provider, options });
        throw new Error("requireAuth");
      },
    };

    expect(() => requireAuthOnUnauthorized({ status: 401 }, ctx, auth)).toThrow("requireAuth");
    expect(seen).toEqual([
      {
        provider: auth,
        options: { reason: "The provider rejected the connection credential with 401." },
      },
    ]);
  });

  it("leaves other statuses to the tool", () => {
    const ctx = {
      requireAuth(): never {
        throw new Error("must not be called");
      },
    };

    expect(() => requireAuthOnUnauthorized({ status: 200 }, ctx, {})).not.toThrow();
    expect(() => requireAuthOnUnauthorized({ status: 500 }, ctx, {})).not.toThrow();
  });
});
