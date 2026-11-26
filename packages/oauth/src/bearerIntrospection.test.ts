import { describe, it, expect, jest, afterEach } from "@jest/globals";
import { configureBearerIntrospection } from "./bearerIntrospection.js";
import { ClientSecret } from "./server/clientSecret.js";

const issuer = "https://zone.keycard.cloud";
const credential = new ClientSecret("server", "secret");

describe("bearer introspection plumbing", () => {
  afterEach(() => jest.restoreAllMocks());

  it("logs each failure once without logging authorization server descriptions", async () => {
    const warn = jest.spyOn(console, "warn").mockImplementation(() => {});
    const transport = jest.fn<typeof fetch>(async (input) =>
      String(input).endsWith("/oauth-authorization-server")
        ? Response.json({ issuer, introspection_endpoint: issuer + "/introspect" })
        : Response.json({ error: "invalid_client", error_description: "sensitive detail" }, { status: 401 }),
    );
    const configuration = { introspect: true, credential: { [issuer]: credential }, introspectionFetch: transport };
    const check = configureBearerIntrospection(configuration, true)!;
    await expect(check(issuer, "caller-token")).rejects.toMatchObject({ status: 503 });
    await expect(check(issuer, "caller-token")).rejects.toMatchObject({ status: 503 });
    await expect(check("https://other.keycard.cloud", "caller-token")).rejects.toMatchObject({ status: 503 });
    await expect(check("https://other.keycard.cloud", "caller-token")).rejects.toMatchObject({ status: 503 });
    expect(warn.mock.calls).toEqual([
      ["Bearer token introspection failed:", "invalid_client (HTTP 401)"],
      ["Bearer token introspection failed:", "No credential for the verified issuer"],
    ]);
    expect(transport.mock.calls.map(([input]) => String(input))).toEqual([
      issuer + "/.well-known/oauth-authorization-server",
      issuer + "/introspect",
      issuer + "/introspect",
    ]);
  });

  it.each([[issuer + "/", issuer], [issuer, issuer + "/"]])(
    "bearer row 18: matches issuer-keyed credentials with or without a trailing slash (%s, %s)",
    async (key, verifiedIssuer) => {
      const transport = jest.fn<typeof fetch>(async (input) =>
        String(input).endsWith("/oauth-authorization-server")
          ? Response.json({ issuer, introspection_endpoint: issuer + "/introspect" })
          : Response.json({ active: true }),
      );
      const check = configureBearerIntrospection({
        introspect: true, credential: { [key]: credential }, introspectionFetch: transport,
      }, true)!;
      await expect(check(verifiedIssuer, "caller-token")).resolves.toBe(true);
      expect(transport).toHaveBeenLastCalledWith(issuer + "/introspect", expect.objectContaining({
        headers: expect.objectContaining({ Authorization: `Basic ${btoa("server:secret")}` }),
      }));
    },
  );

  it("bearer row 22: caches resolved discovery per issuer but never caches token status", async () => {
    const other = "https://other.keycard.cloud";
    const post = jest.fn()
      .mockReturnValueOnce(Response.json({ active: true }))
      .mockReturnValueOnce(Response.json({ active: false }))
      .mockReturnValueOnce(Response.json({ active: true }));
    const discover = jest.fn((iss: string) => Response.json({ issuer: iss, introspection_endpoint: iss + "/introspect" }));
    const transport = jest.fn<typeof fetch>(async (input) => {
      const url = new URL(String(input));
      return url.pathname === "/introspect" ? post() as Response : discover(url.origin);
    });
    const check = configureBearerIntrospection({
      introspect: true, credential: { [issuer]: credential, [other]: credential }, introspectionFetch: transport,
    }, true)!;
    await expect(check(issuer, "caller-token")).resolves.toBe(true);
    await expect(check(issuer, "caller-token")).resolves.toBe(false);
    await expect(check(other, "caller-token")).resolves.toBe(true);
    expect(discover.mock.calls).toEqual([[issuer], [other]]);
    expect(post).toHaveBeenCalledTimes(3);
  });

  it("bearer row 22: a stalled discovery does not block a later check for the same issuer", async () => {
    const transport = jest.fn<typeof fetch>()
      .mockImplementationOnce(() => new Promise<Response>(() => {}))
      .mockResolvedValueOnce(Response.json({ issuer, introspection_endpoint: issuer + "/introspect" }))
      .mockResolvedValueOnce(Response.json({ active: true }));
    const check = configureBearerIntrospection({
      introspect: true, credential, introspectionFetch: transport,
    }, false)!;
    void check(issuer, "first-token");
    const second = check(issuer, "second-token");
    expect(transport.mock.calls.map(([input]) => String(input))).toEqual([
      issuer + "/.well-known/oauth-authorization-server",
      issuer + "/.well-known/oauth-authorization-server",
    ]);
    await expect(second).resolves.toBe(true);
  });

  it("bearer row 20: drops failed discovery and retries only on a later request after the retry delay", async () => {
    jest.spyOn(console, "warn").mockImplementation(() => {});
    const now = jest.spyOn(performance, "now").mockReturnValue(0);
    const transport = jest.fn<typeof fetch>()
      .mockResolvedValueOnce(new Response(null, { status: 503, headers: { "Retry-After": "1" } }))
      .mockResolvedValueOnce(Response.json({ issuer, introspection_endpoint: issuer + "/introspect" }))
      .mockResolvedValueOnce(Response.json({ active: true }));
    const check = configureBearerIntrospection({
      introspect: true, credential, introspectionFetch: transport,
    }, false)!;
    await expect(check(issuer, "caller-token")).rejects.toMatchObject({ status: 503 });
    await expect(check(issuer, "caller-token")).rejects.toMatchObject({ status: 503 });
    expect(transport).toHaveBeenCalledTimes(1);
    now.mockReturnValue(1_001);
    await expect(check(issuer, "caller-token")).resolves.toBe(true);
    expect(transport.mock.calls.map(([input]) => String(input))).toEqual([
      issuer + "/.well-known/oauth-authorization-server",
      issuer + "/.well-known/oauth-authorization-server",
      issuer + "/introspect",
    ]);
  });

  it("uses a caller's shorter timeout for introspection discovery", async () => {
    jest.spyOn(console, "warn").mockImplementation(() => {});
    const timeout = jest.spyOn(AbortSignal, "timeout");
    const transport = jest.fn<typeof fetch>(async (_input, init) => {
      await new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(init.signal?.reason), { once: true });
      });
      throw new Error("Unexpected successful request");
    });
    const check = configureBearerIntrospection({
      introspect: true, credential, introspectionTimeoutMs: 15, introspectionFetch: transport,
    }, false)!;
    await expect(check(issuer, "caller-token")).rejects.toMatchObject({ status: 503 });
    expect(timeout).toHaveBeenCalledWith(15);
    expect(transport).toHaveBeenCalledTimes(1);
  });
});
