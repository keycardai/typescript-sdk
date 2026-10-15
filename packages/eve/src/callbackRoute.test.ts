import { describe, expect, it } from "@jest/globals";

import {
  decodeCallbackState,
  encodeCallbackState,
  keycardCallbackRoute,
} from "./callbackRoute.js";

const ORIGIN = "https://agent.example.com";
const ATTEMPT_CALLBACK = `${ORIGIN}/eve/v1/connections/docs/callback/attempt-1/token-1`;
const ROUTE = `${ORIGIN}/keycard/callback`;

const handlerArgs = {} as never;

async function call(
  route: ReturnType<typeof keycardCallbackRoute>,
  query: Record<string, string>,
  base = ROUTE,
): Promise<Response> {
  const url = new URL(base);
  for (const [key, value] of Object.entries(query)) {
    url.searchParams.set(key, value);
  }
  return route.handler(new Request(url.toString()), handlerArgs);
}

describe("keycardCallbackRoute", () => {
  it("is the plain route object eve's GET() returns, at the default path", () => {
    const route = keycardCallbackRoute();
    expect(route.transport).toBe("http");
    expect(route.method).toBe("GET");
    expect(route.path).toBe("/keycard/callback");
    expect(keycardCallbackRoute({ path: "/auth/keycard" }).path).toBe("/auth/keycard");
  });

  it("row 45: forwards a success callback to the attempt URL with every parameter unchanged", async () => {
    const state = encodeCallbackState("random-1", ATTEMPT_CALLBACK);
    const response = await call(keycardCallbackRoute(), {
      code: "auth-code",
      state,
      iss: "https://zone.example.com",
    });

    expect(response.status).toBe(302);
    const location = new URL(response.headers.get("Location")!);
    expect(`${location.origin}${location.pathname}`).toBe(ATTEMPT_CALLBACK);
    expect(location.searchParams.get("code")).toBe("auth-code");
    expect(location.searchParams.get("state")).toBe(state);
    expect(location.searchParams.get("iss")).toBe("https://zone.example.com");
  });

  it("row 45: forwards a refusal (error, error_description) the same way", async () => {
    const state = encodeCallbackState("random-1", ATTEMPT_CALLBACK);
    const response = await call(keycardCallbackRoute(), {
      error: "access_denied",
      error_description: "The user declined",
      state,
    });

    expect(response.status).toBe(302);
    const location = new URL(response.headers.get("Location")!);
    expect(`${location.origin}${location.pathname}`).toBe(ATTEMPT_CALLBACK);
    expect(location.searchParams.get("error")).toBe("access_denied");
    expect(location.searchParams.get("error_description")).toBe("The user declined");
    expect(location.searchParams.get("state")).toBe(state);
  });

  it("row 46: refuses another origin, another path, and a malformed state with 400 and no Location", async () => {
    const route = keycardCallbackRoute();
    const otherOrigin = encodeCallbackState(
      "r",
      "https://evil.example.com/eve/v1/connections/docs/callback/a/t",
    );
    const otherPath = encodeCallbackState("r", `${ORIGIN}/admin/callback/a/t`);
    const notCallback = encodeCallbackState("r", `${ORIGIN}/eve/v1/connections/docs/a/t`);

    for (const state of [otherOrigin, otherPath, notCallback, "random-only", "", "a.%%%"]) {
      const response = await call(route, { code: "auth-code", state });
      expect(response.status).toBe(400);
      expect(response.headers.has("Location")).toBe(false);
    }
    const missing = await call(route, { code: "auth-code" });
    expect(missing.status).toBe(400);
    expect(missing.headers.has("Location")).toBe(false);
  });

  it("compares against a configured public origin when the request origin differs", async () => {
    const state = encodeCallbackState("random-1", ATTEMPT_CALLBACK);
    const proxied = keycardCallbackRoute({ origin: ORIGIN });
    const ok = await call(proxied, { code: "c", state }, "http://10.0.0.5:3000/keycard/callback");
    expect(ok.status).toBe(302);
    const plain = await call(keycardCallbackRoute(), { code: "c", state }, "http://10.0.0.5:3000/keycard/callback");
    expect(plain.status).toBe(400);
  });

  it("round-trips the attempt callback URL through state", () => {
    const state = encodeCallbackState("random-1", ATTEMPT_CALLBACK);
    expect(state.startsWith("random-1.")).toBe(true);
    expect(decodeCallbackState(state)).toBe(ATTEMPT_CALLBACK);
    expect(decodeCallbackState("random-1")).toBeUndefined();
    expect(decodeCallbackState(".abc")).toBeUndefined();
  });
});
