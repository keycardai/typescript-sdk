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
