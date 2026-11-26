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
