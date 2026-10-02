import { afterEach, beforeEach, describe, expect, it, jest } from "@jest/globals";
import { TokenType } from "@keycardai/oauth";
import { WorkloadIdentity, WorkloadIdentityRuntimeError } from "@keycardai/oauth/server";

import { asSelf, impersonate } from "./connections.js";
import { FailureReason } from "./errors.js";
import { appPrincipal, connectionContext, fakeZoneClient, validJwt } from "./testing/testUtils.js";
import { vercelOidcTokenSource, VERCEL_OIDC_SOURCE } from "./vercel.js";

const ZONE = "https://abc123.keycard.cloud";
const TOKEN_ENDPOINT = `${ZONE}/oauth/2/token`;
const CALENDAR = "https://calendar.example.com";
const connection = connectionContext();

describe("the Vercel OIDC default credential", () => {
  const saved = { ...process.env };
  const realFetch = globalThis.fetch;
  let bodies: URLSearchParams[];
  let oidcToken: string;

  beforeEach(() => {
    oidcToken = validJwt(3600, { sub: "owner:team:project:agent:environment:production" });
    process.env.KEYCARD_ZONE_URL = ZONE;
    process.env.VERCEL_OIDC_TOKEN = oidcToken;
    bodies = [];
    globalThis.fetch = jest.fn(async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
      const url = String(input);
      if (url.includes("/.well-known/")) {
        return Response.json({ issuer: ZONE, token_endpoint: TOKEN_ENDPOINT });
      }
      if (url === TOKEN_ENDPOINT) {
        bodies.push(new URLSearchParams(String(init?.body)));
        return Response.json({ access_token: "zone-token", token_type: "Bearer", expires_in: 300 });
      }
      throw new Error(`unexpected fetch: ${url}`);
    }) as unknown as typeof fetch;
  });

  afterEach(() => {
    process.env = { ...saved };
    globalThis.fetch = realFetch;
  });

  it("authenticates an impersonation with the deployment's OIDC token", async () => {
    const auth = impersonate({ resource: CALENDAR, userIdentifier: "owner@example.com" });

    const result = await auth.getToken({ principal: appPrincipal(), connection });

    expect(result.token).toBe("zone-token");
    expect(bodies).toHaveLength(1);
    expect(bodies[0]!.get("subject_token_type")).toBe(TokenType.SUBSTITUTE_USER);
    expect(bodies[0]!.get("client_assertion")).toBe(oidcToken);
    expect(bodies[0]!.get("client_assertion_type")).toBe(
      "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    );
  });

  it("authenticates the app's own client credentials grant the same way", async () => {
    await asSelf({ resource: CALENDAR }).getToken({ principal: appPrincipal(), connection });

    expect(bodies[0]!.get("grant_type")).toBe("client_credentials");
    expect(bodies[0]!.get("client_assertion")).toBe(oidcToken);
  });

  it("is replaced by an explicit credential", async () => {
    const auth = impersonate({
      resource: CALENDAR,
      userIdentifier: "owner@example.com",
      applicationCredential: new WorkloadIdentity(() => "other-platform-jwt"),
    });

    await auth.getToken({ principal: appPrincipal(), connection });

    expect(bodies[0]!.get("client_assertion")).toBe("other-platform-jwt");
  });
});

describe("a missing Vercel OIDC token", () => {
  const missing = vercelOidcTokenSource(() => {
    throw new Error("The 'x-vercel-oidc-token' header is missing from the request.");
  });

  it("names the fixes instead of the missing header", async () => {
    const failure = (async () => missing())();

    await expect(failure).rejects.toBeInstanceOf(WorkloadIdentityRuntimeError);
    await expect(failure).rejects.toMatchObject({ source: VERCEL_OIDC_SOURCE });
    await expect(failure).rejects.toThrow("pass `applicationCredential`");
  });

  it("fails the connection as a deployment fault, not a user's", async () => {
    const auth = asSelf({
      resource: CALENDAR,
      client: fakeZoneClient(),
      applicationCredential: new WorkloadIdentity(missing),
    });

    await expect(auth.getToken({ principal: appPrincipal(), connection })).rejects.toMatchObject({
      name: "ConnectionAuthorizationFailedError",
      reason: FailureReason.WORKLOAD_IDENTITY_UNAVAILABLE,
      retryable: false,
    });
  });
});
