import { afterEach, beforeAll, describe, expect, it, jest } from "@jest/globals";
import { generateKeyPairSync, verify } from "node:crypto";
import { pollDeviceToken, requestDeviceAuthorization } from "@keycardai/oauth/deviceAuthorization";
import { ConfigurationError } from "@keycardai/oauth/errors";
import { TokenExchangeClient } from "@keycardai/oauth/tokenExchange";
import { refreshAuthorization } from "@keycardai/oauth/webApp";
import { IsolateSafeTokenCache, resolveCredential, WorkersClientSecret } from "../index.js";

const ISSUER = "https://zone.example.test";
const DEVICE_ENDPOINT = `${ISSUER}/oauth/device`;
const TOKEN_ENDPOINT = `${ISSUER}/oauth/token`;
const DISCOVERY_URL = `${ISSUER}/.well-known/oauth-authorization-server`;
const RESOURCE = "https://api.example.test";
const SECOND_RESOURCE = "https://other-api.example.test";
const CLIENT_ID = "client-abc";
const JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";
const METADATA = { issuer: ISSUER, token_endpoint: TOKEN_ENDPOINT, device_authorization_endpoint: DEVICE_ENDPOINT };
const TOKEN_RESPONSE = { access_token: "access-token", token_type: "Bearer", expires_in: 60 };
const DEVICE_RESPONSE = { device_code: "device-code", user_code: "CODE", verification_uri: `${ISSUER}/device`, expires_in: 600 };

let privateKey: string;
let publicKey: string;

beforeAll(() => {
  ({ privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  }));
});

afterEach(() => jest.restoreAllMocks());

function webIdentity() {
  return resolveCredential({ KEYCARD_ISSUER: ISSUER, KEYCARD_PRIVATE_KEY: privateKey, KEYCARD_CLIENT_ID: CLIENT_ID });
}

function stubZone() {
  const calls: { url: string; method?: string; headers: Headers; form: URLSearchParams }[] = [];
  jest.spyOn(globalThis, "fetch").mockImplementation(async (url, init) => {
    if (String(url) === DISCOVERY_URL) return Response.json(METADATA);
    calls.push({
      url: String(url),
      method: init?.method,
      headers: new Headers(init?.headers),
      form: new URLSearchParams(String(init?.body ?? "")),
    });
    return Response.json(String(url) === DEVICE_ENDPOINT ? DEVICE_RESPONSE : TOKEN_RESPONSE);
  });
  return calls;
}

function expectAssertion(call: ReturnType<typeof stubZone>[number], audience: string) {
  expect(call.headers.has("Authorization")).toBe(false);
  expect(call.form.get("client_assertion_type")).toBe(JWT_BEARER);
  expect(call.form.has("client_id")).toBe(false);
  const assertion = call.form.get("client_assertion")!;
  const [encodedHeader, payload, signature] = assertion.split(".");
  const header = JSON.parse(Buffer.from(encodedHeader, "base64url").toString());
  const claims = JSON.parse(Buffer.from(payload, "base64url").toString());
  expect(header).toMatchObject({ alg: "RS256", kid: "worker-key" });
  expect(verify("RSA-SHA256", Buffer.from(`${encodedHeader}.${payload}`), publicKey, Buffer.from(signature, "base64url"))).toBe(true);
  expect(claims).toMatchObject({ iss: CLIENT_ID, sub: CLIENT_ID, aud: audience });
  return claims;
}

describe("Workers token exchange (web-identity.md)", () => {
  it("row 4: signs a cached exchange's assertion as the configured client for the discovered token endpoint (SDK-112)", async () => {
    const calls = stubZone();
    const credential = webIdentity();
    const cache = new IsolateSafeTokenCache(new TokenExchangeClient(ISSUER, { credential }), { credential });

    await expect(cache.getToken("user-1", "subject-token", RESOURCE)).resolves.toMatchObject({
      accessToken: TOKEN_RESPONSE.access_token,
    });
    expect(calls.map(({ url }) => url)).toEqual([TOKEN_ENDPOINT]);
    expect(calls[0].form.get("subject_token")).toBe("subject-token");
    expect(calls[0].form.get("resource")).toBe(RESOURCE);
    const claims = expectAssertion(calls[0], TOKEN_ENDPOINT);
    expect(claims).toMatchObject({ jti: expect.any(String), iat: expect.any(Number), exp: claims.iat + 300 });
  });
});

const credentialCases = [
  { name: "WorkersClientSecret", create: () => new WorkersClientSecret(CLIENT_ID, "secret") },
  { name: "WorkersWebIdentity", create: webIdentity },
];

describe.each(credentialCases)("$name", ({ name, create }) => {
  function expectClientAuthentication(call: ReturnType<typeof stubZone>[number], endpoint: string) {
    expect(call.form.has("subject_token_type")).toBe(false);
    if (name === "WorkersClientSecret") {
      expect(call.headers.get("Authorization")).toBe(`Basic ${btoa(`${CLIENT_ID}:secret`)}`);
      expect(call.form.has("client_assertion")).toBe(false);
      expect(call.form.has("client_id")).toBe(false);
      return undefined;
    }
    return expectAssertion(call, endpoint).jti;
  }

  it("row 1: authenticates device authorization and polling with the Workers credential (SDK-132)", async () => {
    const calls = stubZone();
    const credential = create();
    const authorization = await requestDeviceAuthorization(ISSUER, {
      credential,
      metadata: METADATA,
      scopes: ["openid", "profile"],
      resources: [RESOURCE, SECOND_RESOURCE],
    });
    await expect(pollDeviceToken(ISSUER, { credential, metadata: METADATA, authorization })).resolves.toMatchObject({
      accessToken: TOKEN_RESPONSE.access_token,
    });

    expect(calls.map(({ url, method }) => [url, method])).toEqual([[DEVICE_ENDPOINT, "POST"], [TOKEN_ENDPOINT, "POST"]]);
    const [device, poll] = calls;
    expect(device.form.get("scope")).toBe("openid profile");
    expect(device.form.getAll("resource")).toEqual([RESOURCE, SECOND_RESOURCE]);
    expect(poll.form.get("grant_type")).toBe(DEVICE_GRANT);
    expect(poll.form.get("device_code")).toBe(DEVICE_RESPONSE.device_code);
    expect(poll.form.has("resource")).toBe(false);
    expect(poll.form.has("scope")).toBe(false);
    const deviceJti = expectClientAuthentication(device, DEVICE_ENDPOINT);
    const pollJti = expectClientAuthentication(poll, TOKEN_ENDPOINT);
    if (name === "WorkersWebIdentity") {
      expect(deviceJti).toEqual(expect.any(String));
      expect(pollJti).toEqual(expect.any(String));
      expect(pollJti).not.toBe(deviceJti);
    }
  });

  it("row 16: authenticates a refresh with the Workers credential (SDK-132)", async () => {
    const calls = stubZone();
    const credential = create();
    const options = { credential, metadata: METADATA, refreshToken: "refresh-token", resources: [RESOURCE] };
    await expect(refreshAuthorization(ISSUER, { ...options, clientId: CLIENT_ID } as never)).rejects.toThrow(
      ConfigurationError,
    );
    expect(calls).toHaveLength(0);

    await expect(refreshAuthorization(ISSUER, options)).resolves.toMatchObject({
      accessToken: TOKEN_RESPONSE.access_token,
    });

    expect(calls.map(({ url, method }) => [url, method])).toEqual([[TOKEN_ENDPOINT, "POST"]]);
    expect(calls[0].form.get("grant_type")).toBe("refresh_token");
    expect(calls[0].form.get("refresh_token")).toBe("refresh-token");
    expect(calls[0].form.getAll("resource")).toEqual([RESOURCE]);
    expectClientAuthentication(calls[0], TOKEN_ENDPOINT);
  });
});
