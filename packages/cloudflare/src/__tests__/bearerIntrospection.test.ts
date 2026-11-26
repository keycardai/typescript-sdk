import { describe, expect, it, jest, beforeAll, afterEach } from "@jest/globals";
import { JWTSigner } from "@keycardai/oauth/jwt/signer";
import { ConfigurationError } from "@keycardai/oauth/errors";
import { verifyBearerToken, verifyRequest } from "../auth.js";
import { WorkersClientSecret, WorkersWebIdentity } from "../credentials.js";
import type { BearerAuthOptions, KeycardWorkerOptions } from "../types.js";
import { createKeycardWorker } from "../worker.js";

const issuer = "https://introspection-worker.keycard.cloud";
const resource = "https://worker.example/mcp";
const endpoint = "/oauth/introspection";
const kid = "worker-introspection-key";
const credential = new WorkersClientSecret("resource-owner", "secret");

let signer: JWTSigner;
let jwks: { keys: JsonWebKey[] };

beforeAll(async () => {
  const pair = await crypto.subtle.generateKey({
    name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256",
  }, true, ["sign", "verify"]);
  signer = new JWTSigner({ key: async () => ({ key: pair.privateKey, kid, issuer }) });
  const publicKey = await crypto.subtle.exportKey("jwk", pair.publicKey);
  jwks = { keys: [{ ...publicKey, kid, alg: "RS256", use: "sig" }] };
});

afterEach(() => jest.restoreAllMocks());

async function bearerRequest(iss = issuer, aud: string | string[] = resource) {
  const now = Math.floor(Date.now() / 1000);
  const token = await signer.sign({
    iss, aud, sub: "user", client_id: "calling-client", iat: now, exp: now + 60,
  });
  return new Request(resource, { headers: { authorization: `Bearer ${token}` } });
}

function stubZone(replies: Array<() => Response> = []) {
  const post = jest.fn((url: string, _init?: RequestInit) => replies.shift()?.() ?? Response.json({ active: true }));
  jest.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const url = new URL(String(input instanceof Request ? input.url : input));
    if (url.pathname === "/.well-known/oauth-authorization-server") {
      return Response.json({
        issuer: url.origin, jwks_uri: url.origin + "/jwks", token_endpoint: url.origin + "/oauth/token",
        introspection_endpoint: url.origin + endpoint,
      });
    }
    if (url.pathname === "/jwks") return Response.json(jwks);
    if (url.pathname === endpoint) return post(url.href, init);
    throw new Error("Unexpected outbound request");
  });
  return post;
}

function worker(options: Partial<KeycardWorkerOptions>) {
  const handler = jest.fn(() => new Response("handler", { status: 200 }));
  const app = createKeycardWorker({ resourceIdentifier: resource, ...options, fetch: handler });
  return {
    handler,
    send: async (request?: Request) =>
      app.fetch!(request ?? await bearerRequest(), { KEYCARD_ISSUER: issuer }, {} as ExecutionContext),
  };
}

describe("Workers bearer introspection", () => {
  it("cloudflare-workers row 1 and bearer row 21: skips introspection by default and when explicitly false", async () => {
    const post = stubZone();
    for (const options of [{}, { introspect: false }]) {
      const app = worker(options);
      expect((await app.send()).status).toBe(200);
      expect(app.handler).toHaveBeenCalledTimes(1);
    }
    expect(post).not.toHaveBeenCalled();
  });

  it("cloudflare-workers row 2, cloudflare-workers integration row 1 and bearer row 18: uses the owner credential for another client's token", async () => {
    const post = stubZone();
    const app = worker({ introspect: true, credential });
    const request = await bearerRequest();
    expect(await (await app.send(request)).text()).toBe("handler");
    expect(post).toHaveBeenCalledTimes(1);
    const [url, init] = post.mock.calls[0];
    expect(url).toBe(issuer + endpoint);
    expect(init?.method).toBe("POST");
    expect(new Headers(init?.headers).get("authorization")).toBe(`Basic ${btoa("resource-owner:secret")}`);
    expect(new URLSearchParams(String(init?.body)).get("token")).toBe(request.headers.get("authorization")?.slice(7));
    expect(app.handler).toHaveBeenCalledTimes(1);
  });

  it("cloudflare-workers row 3 and bearer row 19: denies an inactive token with the configured challenge", async () => {
    const post = stubZone([() => Response.json({ active: false })]);
    const app = worker({ introspect: true, credential });
    const response = await app.send(await bearerRequest(issuer, ["https://another.example", resource]));
    expect(response.status).toBe(401);
    expect(response.headers.get("WWW-Authenticate")).toBe(
      'Bearer error="invalid_token", error_description="Token is inactive", resource_metadata="https://worker.example/.well-known/oauth-protected-resource/mcp"',
    );
    expect(post).toHaveBeenCalledTimes(1);
    expect(app.handler).not.toHaveBeenCalled();
  });

  it("cloudflare-workers row 4 and bearer row 20: maps a failed check to 503 with no challenge", async () => {
    const post = stubZone([() => Response.json({ error: "invalid_client" }, { status: 401 })]);
    const app = worker({ introspect: true, credential });
    const response = await app.send();
    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({ error: "temporarily_unavailable" });
    expect(response.headers.has("WWW-Authenticate")).toBe(false);
    expect(post).toHaveBeenCalledTimes(1);
    expect(app.handler).not.toHaveBeenCalled();
  });

  it("cloudflare-workers row 3: direct verifyRequest rejects an inactive token when introspection is enabled", async () => {
    const post = stubZone([() => Response.json({ active: false })]);
    const response = await verifyRequest(await bearerRequest(), {
      issuers: issuer, resourceIdentifier: resource, introspect: true, credential,
    });
    expect(response).toBeInstanceOf(Response);
    if (!(response instanceof Response)) throw new Error("Expected an authentication response");
    expect(response.status).toBe(401);
    expect(response.headers.get("WWW-Authenticate")).toContain('error="invalid_token"');
    expect(post).toHaveBeenCalledTimes(1);
  });

  it("bearer row 22: direct verifyRequest reuses discovery but checks token status on every call", async () => {
    const post = stubZone([() => Response.json({ active: true }), () => Response.json({ active: false })]);
    const fetch = jest.fn(globalThis.fetch);
    const options = {
      issuers: issuer, resourceIdentifier: resource, introspect: true, credential, introspectionFetch: fetch,
    };
    const request = await bearerRequest();
    expect(await verifyRequest(request, options)).not.toBeInstanceOf(Response);
    expect(await verifyRequest(request, options)).toMatchObject({ status: 401 });
    expect(fetch.mock.calls.filter(([url]) =>
      String(url).endsWith("/.well-known/oauth-authorization-server"))).toHaveLength(1);
    expect(post).toHaveBeenCalledTimes(2);
  });

  it("cloudflare-workers row 5 and bearer row 23: rejects an unauthenticating credential at construction", () => {
    expect(() => worker({ introspect: true, credential: new WorkersWebIdentity("key-without-client-id") }))
      .toThrow(ConfigurationError);
    expect(() => worker({ introspect: true })).toThrow(ConfigurationError);
  });

  it("bearer row 21 and bearer row 25: skips the remote check on invalid tokens or inadequate scopes", async () => {
    const post = stubZone();
    const app = worker({ introspect: true, credential, requiredScopes: ["read"] });
    expect((await app.send(await bearerRequest(issuer, "https://another.example"))).status).toBe(401);
    const response = await app.send();
    expect(response.status).toBe(403);
    expect(response.headers.get("WWW-Authenticate")).toContain('error="insufficient_scope"');
    expect(app.handler).not.toHaveBeenCalled();
    expect(post).not.toHaveBeenCalled();
  });

  it("bearer row 22: checks the same token again instead of caching an active response", async () => {
    const post = stubZone([() => Response.json({ active: true }), () => Response.json({ active: false })]);
    const app = worker({ introspect: true, credential });
    const request = await bearerRequest();
    expect((await app.send(request)).status).toBe(200);
    expect((await app.send(request)).status).toBe(401);
    expect(post).toHaveBeenCalledTimes(2);
    expect(app.handler).toHaveBeenCalledTimes(1);
  });

  it("bearer rows 23 and 24: rejects an unkeyed credential and fails closed for an issuer with no credential", async () => {
    const post = stubZone();
    const other = "https://other-introspection-worker.keycard.cloud";
    const options: BearerAuthOptions = { issuers: [issuer, other], resourceIdentifier: resource, introspect: true };
    const request = await bearerRequest();
    await expect(verifyBearerToken(request, { ...options, credential })).rejects.toThrow(ConfigurationError);
    const keyed: BearerAuthOptions = { ...options, credential: { [issuer]: credential } };
    expect(await verifyBearerToken(request, keyed)).not.toBeInstanceOf(Response);
    const response = await verifyBearerToken(await bearerRequest(other), keyed) as Response;
    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({ error: "temporarily_unavailable" });
    expect(response.headers.has("WWW-Authenticate")).toBe(false);
    expect(post).toHaveBeenCalledTimes(1);
    expect(post.mock.calls[0][0]).toBe(issuer + endpoint);
  });
});
