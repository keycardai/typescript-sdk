import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { WebIdentity } from "./webIdentity.js";

describe("WebIdentity default storage directory", () => {
  let tmp: string;
  let prevCwd: string;

  beforeEach(() => {
    prevCwd = process.cwd();
    tmp = mkdtempSync(join(tmpdir(), "webidentity-"));
    process.chdir(tmp);
  });

  afterEach(() => {
    process.chdir(prevCwd);
    rmSync(tmp, { recursive: true, force: true });
  });

  it("defaults to ./server_keys", async () => {
    const wi = new WebIdentity({ serverName: "svc" });
    await wi.bootstrap();

    expect(readdirSync(join(tmp, "server_keys")).length).toBeGreaterThan(0);
    expect(existsSync(join(tmp, "mcp_keys"))).toBe(false);
  });

  it("falls back to ./mcp_keys when it exists and ./server_keys does not", async () => {
    mkdirSync(join(tmp, "mcp_keys"));

    const wi = new WebIdentity({ serverName: "svc" });
    await wi.bootstrap();

    expect(readdirSync(join(tmp, "mcp_keys")).length).toBeGreaterThan(0);
    expect(existsSync(join(tmp, "server_keys"))).toBe(false);
  });

  it("honors an explicit storageDir over the default", async () => {
    const wi = new WebIdentity({ serverName: "svc", storageDir: "custom_keys" });
    await wi.bootstrap();

    expect(readdirSync(join(tmp, "custom_keys")).length).toBeGreaterThan(0);
    expect(existsSync(join(tmp, "server_keys"))).toBe(false);
  });
});

function decodeJwtPayload(jwt: string): Record<string, unknown> {
  const payload = jwt.split(".")[1];
  return JSON.parse(Buffer.from(payload, "base64url").toString("utf-8"));
}

describe("WebIdentity client assertion (iss/sub/aud)", () => {
  const TOKEN_ENDPOINT = "https://acme.keycard.cloud/oauth/2/token";
  let tmp: string;

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), "webidentity-assert-"));
  });

  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  it("signs iss=sub=clientId and aud=token endpoint", async () => {
    const wi = new WebIdentity({ clientId: "cred-abc", storageDir: tmp });
    const req = await wi.prepareTokenExchangeRequest(
      "subject-token",
      "https://api.example.com",
      { tokenEndpoint: TOKEN_ENDPOINT },
    );

    expect(req.clientAssertion).toBeDefined();
    const payload = decodeJwtPayload(req.clientAssertion!);
    expect(payload.iss).toBe("cred-abc");
    expect(payload.sub).toBe("cred-abc");
    expect(payload.aud).toBe(TOKEN_ENDPOINT);
  });

  it("prefers an explicit resource_client_id over the configured clientId", async () => {
    const wi = new WebIdentity({ clientId: "cred-abc", storageDir: tmp });
    const req = await wi.prepareTokenExchangeRequest(
      "subject-token",
      "https://api.example.com",
      { tokenEndpoint: TOKEN_ENDPOINT, authInfo: { resource_client_id: "cred-override" } },
    );

    const payload = decodeJwtPayload(req.clientAssertion!);
    expect(payload.iss).toBe("cred-override");
    expect(payload.sub).toBe("cred-override");
  });

  it("throws when no clientId is configured", async () => {
    const wi = new WebIdentity({ storageDir: tmp });
    await expect(
      wi.prepareTokenExchangeRequest("subject-token", "https://api.example.com", {
        tokenEndpoint: TOKEN_ENDPOINT,
      }),
    ).rejects.toThrow(/clientId is required/);
  });

  it("throws when no token endpoint is supplied", async () => {
    const wi = new WebIdentity({ clientId: "cred-abc", storageDir: tmp });
    await expect(
      wi.prepareTokenExchangeRequest("subject-token", "https://api.example.com", {}),
    ).rejects.toThrow(/token endpoint is required/);
  });
});
