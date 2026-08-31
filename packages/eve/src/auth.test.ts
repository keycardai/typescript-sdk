import { describe, expect, it } from "@jest/globals";
import type { AuthFn } from "eve/channels/auth";
import type { SessionAuthContext } from "eve/context";

import { keycardAuth } from "./auth.js";
import { onBehalfOf } from "./connections.js";
import { memorySubjectTokenStore, SUBJECT_TOKEN_ATTRIBUTE } from "./subjectTokens.js";
import {
  bearerRequest,
  fakeVerifier,
  fakeZoneClient,
  unsignedJwt,
  userPrincipal,
  validJwt,
} from "./testing/testUtils.js";

const ZONE = "https://zone.example.com";
const CALENDAR = "https://calendar.example.com";

/** eve's ordered walk: first non-null context wins, a thrown response stops it. */
async function walk(
  request: Request,
  auth: readonly AuthFn<Request>[],
): Promise<SessionAuthContext | Response> {
  for (const entry of auth) {
    try {
      const context = await entry(request);
      if (context) return context;
    } catch (error) {
      const response = (error as { response?: Response }).response;
      if (response) return response;
      throw error;
    }
  }
  return new Response(null, { status: 401 });
}

const localDev: AuthFn<Request> = () => ({
  attributes: {},
  authenticator: "local-dev",
  principalId: "dev",
  principalType: "user",
});

describe("keycardAuth", () => {
  it("wins the ordered auth walk with a valid zone token", async () => {
    const token = validJwt(3600, { iss: ZONE, client_id: "agent", scope: "calendar.read" });
    const auth = keycardAuth({
      zoneUrl: ZONE,
      verify: fakeVerifier(token, {
        iss: ZONE,
        sub: "user-1",
        client_id: "agent",
        scope: "calendar.read",
        email: "user@example.com",
      }),
    });

    const result = await walk(bearerRequest(token), [auth, localDev]);

    expect(result).toEqual({
      attributes: {
        client_id: "agent",
        email: "user@example.com",
        scope: "calendar.read",
      },
      authenticator: "keycard",
      issuer: ZONE,
      principalId: "user-1",
      principalType: "user",
      subject: "user-1",
    });
  });

  it("recognizes zone tokens when zoneUrl carries a trailing slash", async () => {
    const token = validJwt(3600, { iss: ZONE });
    const auth = keycardAuth({
      zoneUrl: `${ZONE}/`,
      verify: fakeVerifier(token, { iss: ZONE, sub: "user-1" }),
    });

    const result = await walk(bearerRequest(token), [auth, localDev]);

    expect(result).toMatchObject({ authenticator: "keycard", principalId: "user-1" });
  });

  it("returns null for a caller the zone did not issue, so the walk continues", async () => {
    const auth = keycardAuth({
      zoneUrl: ZONE,
      verify: async () => {
        throw new Error("verification must not run for a foreign token");
      },
    });

    const foreign = unsignedJwt({ iss: "https://other-idp.example.com", sub: "someone" });
    expect(await auth(bearerRequest(foreign))).toBeNull();
    expect(await auth(bearerRequest("opaque-api-key"))).toBeNull();
    expect(await auth(new Request("https://agent.example.com/chat"))).toBeNull();

    const result = await walk(bearerRequest(foreign), [auth, localDev]);
    expect(result).toMatchObject({ authenticator: "local-dev" });
  });

  it("rejects a zone token that does not verify, instead of falling through", async () => {
    const auth = keycardAuth({
      zoneUrl: ZONE,
      verify: fakeVerifier("the-good-one", { iss: ZONE, sub: "user-1" }),
    });
    const tampered = unsignedJwt({ iss: ZONE, sub: "user-1" });

    const result = await walk(bearerRequest(tampered), [auth, localDev]);

    expect(result).toBeInstanceOf(Response);
    const response = result as Response;
    expect(response.status).toBe(401);
    expect(response.headers.get("www-authenticate")).toBe('Bearer error="invalid_token"');
  });

  it("rejects a token minted for another audience", async () => {
    const token = unsignedJwt({ iss: ZONE, sub: "user-1", aud: "https://other.example.com" });
    const auth = keycardAuth({
      zoneUrl: ZONE,
      audience: CALENDAR,
      verify: async () => {
        throw new Error("Audience not allowed");
      },
    });

    const result = await walk(bearerRequest(token), [auth, localDev]);

    expect(result).toBeInstanceOf(Response);
    expect((result as Response).status).toBe(401);
    await expect(auth(bearerRequest(token))).rejects.toThrow("Audience not allowed");
  });

  it("rejects a token missing a required scope", async () => {
    const token = unsignedJwt({ iss: ZONE, sub: "user-1" });
    const auth = keycardAuth({
      zoneUrl: ZONE,
      requiredScopes: ["calendar.write"],
      verify: fakeVerifier(token, { iss: ZONE, sub: "user-1", scope: "calendar.read" }),
    });

    const result = (await walk(bearerRequest(token), [auth])) as Response;

    expect(result.status).toBe(401);
    expect(result.headers.get("www-authenticate")).toBe('Bearer error="insufficient_scope"');
  });

  it("retains the verified bearer for a later exchange without exposing it", async () => {
    const token = validJwt(3600, { iss: ZONE });
    const store = memorySubjectTokenStore();
    const auth = keycardAuth({
      zoneUrl: ZONE,
      subjectTokens: store,
      verify: fakeVerifier(token, { iss: ZONE, sub: "user-1", client_id: "agent" }),
    });

    const context = (await auth(bearerRequest(token))) as SessionAuthContext;
    expect(Object.values(context.attributes)).not.toContain(token);

    const client = fakeZoneClient();
    const connection = onBehalfOf({
      resource: CALENDAR,
      client,
      subjectTokens: store,
    });
    await connection.getToken({
      principal: userPrincipal(context.principalId, context.issuer),
      connection: { url: "https://mcp.example.com/mcp" },
    });

    expect(client.calls.exchanges[0]?.subjectToken).toBe(token);
  });

  it("puts the bearer on session attributes only when asked", async () => {
    const token = validJwt(3600, { iss: ZONE });
    const auth = keycardAuth({
      zoneUrl: ZONE,
      retainSubjectToken: "attributes",
      verify: fakeVerifier(token, { iss: ZONE, sub: "user-1" }),
    });

    const context = (await auth(bearerRequest(token))) as SessionAuthContext;

    expect(context.attributes[SUBJECT_TOKEN_ATTRIBUTE]).toBe(token);
  });

  it("carries the configured principal type", async () => {
    const token = validJwt(3600, { iss: ZONE });
    const auth = keycardAuth({
      zoneUrl: ZONE,
      principalType: "app",
      verify: fakeVerifier(token, { iss: ZONE, sub: "agent-1" }),
    });

    const context = (await auth(bearerRequest(token))) as SessionAuthContext;

    expect(context.principalType).toBe("app");
  });

  it("requires a zone URL or a verification seam", () => {
    expect(() => keycardAuth({})).toThrow("keycardAuth requires zoneUrl or verify");
  });
});
