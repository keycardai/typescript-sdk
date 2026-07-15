import * as fs from "node:fs";
import * as http from "node:http";
import * as os from "node:os";
import * as path from "node:path";
import {
  DEFAULT_FILE_TOKEN_ENV_VARS,
  FileTokenSource,
  FlyTokenSource,
  GCPMetadataTokenSource,
  WorkloadIdentity,
  WorkloadIdentityConfigurationError,
  WorkloadIdentityRuntimeError,
} from "./workloadIdentity.js";
import { EKSWorkloadIdentity } from "./eksWorkloadIdentity.js";

function makeTokenFile(contents: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "wif-"));
  const file = path.join(dir, "token");
  fs.writeFileSync(file, contents);
  return file;
}

const savedEnv: Record<string, string | undefined> = {};

beforeEach(() => {
  for (const name of DEFAULT_FILE_TOKEN_ENV_VARS) {
    savedEnv[name] = process.env[name];
    delete process.env[name];
  }
});

afterEach(() => {
  for (const name of DEFAULT_FILE_TOKEN_ENV_VARS) {
    if (savedEnv[name] === undefined) {
      delete process.env[name];
    } else {
      process.env[name] = savedEnv[name];
    }
  }
  delete process.env.CUSTOM_TOKEN_FILE;
});

describe("WorkloadIdentity", () => {
  it("rejects a null source at construction", () => {
    expect(() => new WorkloadIdentity(null as never)).toThrow(
      WorkloadIdentityConfigurationError,
    );
  });

  it("rejects a non-callable source at construction", () => {
    expect(() => new WorkloadIdentity({} as never)).toThrow(
      WorkloadIdentityConfigurationError,
    );
  });

  it("uses assertion-based auth, not basic auth", () => {
    const credential = new WorkloadIdentity(async () => "platform-token");
    expect(credential.getAuth()).toBeNull();
  });

  it("prepares the exchange request from the source token", async () => {
    const credential = new WorkloadIdentity(async () => "platform-token");

    const request = await credential.prepareTokenExchangeRequest(
      "subject-token",
      "https://resource.example.com",
    );

    expect(request.clientAssertion).toBe("platform-token");
    expect(request.clientAssertionType).toBe(
      "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    );
    expect(request.subjectToken).toBe("subject-token");
    expect(request.subjectTokenType).toBe("urn:ietf:params:oauth:token-type:access_token");
    expect(request.resource).toBe("https://resource.example.com");
    expect(request.clientId).toBeUndefined();
  });

  it("carries clientId when configured", async () => {
    const credential = new WorkloadIdentity(async () => "platform-token", {
      clientId: "acr_123",
    });

    const request = await credential.prepareTokenExchangeRequest(
      "subject-token",
      "https://resource.example.com",
    );

    expect(request.clientId).toBe("acr_123");
  });

  it("accepts a sync function source", async () => {
    const credential = new WorkloadIdentity(() => "sync-token");

    const request = await credential.prepareTokenExchangeRequest(
      "subject-token",
      "https://resource.example.com",
    );

    expect(request.clientAssertion).toBe("sync-token");
  });

  it("fetches a fresh token on every exchange", async () => {
    let calls = 0;
    const credential = new WorkloadIdentity(async () => `token-${++calls}`);

    for (const expected of [1, 2]) {
      const request = await credential.prepareTokenExchangeRequest(
        "subject-token",
        "https://resource.example.com",
      );
      expect(request.clientAssertion).toBe(`token-${expected}`);
    }
    expect(calls).toBe(2);
  });

  it("wraps a custom source error with the cause preserved", async () => {
    const cause = new Error("socket unavailable");
    const credential = new WorkloadIdentity(async () => {
      throw cause;
    });

    const attempt = credential.prepareTokenExchangeRequest(
      "subject-token",
      "https://resource.example.com",
    );

    await expect(attempt).rejects.toThrow(WorkloadIdentityRuntimeError);
    await attempt.catch((error: WorkloadIdentityRuntimeError) => {
      expect(error.source).toBe("custom");
      expect(error.cause).toBe(cause);
    });
  });

  it("passes through a typed source error untouched", async () => {
    const typed = new WorkloadIdentityRuntimeError("token file is empty", {
      source: "file",
    });
    const credential = new WorkloadIdentity(async () => {
      throw typed;
    });

    await expect(
      credential.prepareTokenExchangeRequest("subject-token", "https://resource.example.com"),
    ).rejects.toBe(typed);
  });

  it("rejects an empty token from the source", async () => {
    const credential = new WorkloadIdentity(async () => "   \n");

    await expect(
      credential.prepareTokenExchangeRequest("subject-token", "https://resource.example.com"),
    ).rejects.toThrow(WorkloadIdentityRuntimeError);
  });
});

describe("FileTokenSource", () => {
  it("uses an explicit path and returns the trimmed token", async () => {
    const file = makeTokenFile("projected-token\n");
    const source = new FileTokenSource({ tokenFilePath: file });

    await expect(source.identityToken()).resolves.toBe("projected-token");
  });

  it("throws a configuration error for a missing file", () => {
    try {
      new FileTokenSource({ tokenFilePath: "/does/not/exist" });
      fail("expected a configuration error");
    } catch (error) {
      expect(error).toBeInstanceOf(WorkloadIdentityConfigurationError);
      expect((error as WorkloadIdentityConfigurationError).source).toBe("file");
      expect((error as WorkloadIdentityConfigurationError).cause).toBeDefined();
    }
  });

  it.each(DEFAULT_FILE_TOKEN_ENV_VARS)("discovers the path from %s", async (envName) => {
    const file = makeTokenFile("discovered-token");
    process.env[envName] = file;

    const source = new FileTokenSource();

    await expect(source.identityToken()).resolves.toBe("discovered-token");
  });

  it("consults a custom env var first", async () => {
    process.env.CUSTOM_TOKEN_FILE = makeTokenFile("custom-token");
    process.env.KEYCARD_EKS_WORKLOAD_IDENTITY_TOKEN_FILE = makeTokenFile("default-token");

    const source = new FileTokenSource({ envVarName: "CUSTOM_TOKEN_FILE" });

    await expect(source.identityToken()).resolves.toBe("custom-token");
  });

  it("throws a configuration error without a path or env var", () => {
    expect(() => new FileTokenSource()).toThrow(WorkloadIdentityConfigurationError);
  });

  it("re-reads the file on every call", async () => {
    const file = makeTokenFile("initial-token");
    const source = new FileTokenSource({ tokenFilePath: file });

    fs.writeFileSync(file, "rotated-token");

    await expect(source.identityToken()).resolves.toBe("rotated-token");
  });

  it("throws a runtime error when the file disappears after construction", async () => {
    const file = makeTokenFile("initial-token");
    const source = new FileTokenSource({ tokenFilePath: file });

    fs.rmSync(file);

    await expect(source.identityToken()).rejects.toThrow(WorkloadIdentityRuntimeError);
  });
});

describe("EKSWorkloadIdentity (deprecated)", () => {
  it("is a WorkloadIdentity", () => {
    const file = makeTokenFile("eks-token");
    const credential = new EKSWorkloadIdentity({ tokenFilePath: file });

    expect(credential).toBeInstanceOf(WorkloadIdentity);
  });

  it("prepares the exchange request with the token file contents", async () => {
    const file = makeTokenFile("eks-token\n");
    const credential = new EKSWorkloadIdentity({ tokenFilePath: file });

    const request = await credential.prepareTokenExchangeRequest(
      "subject-token",
      "https://resource.example.com",
    );

    expect(request.clientAssertion).toBe("eks-token");
    expect(request.clientId).toBeUndefined();
  });

  it("does not discover the Azure variable", () => {
    // The deprecated EKS provider keeps the EKS-only discovery list; the AKS
    // variable is discovered only by FileTokenSource.
    process.env.AZURE_FEDERATED_TOKEN_FILE = makeTokenFile("azure-token");

    expect(() => new EKSWorkloadIdentity()).toThrow(WorkloadIdentityConfigurationError);
    expect(() => new FileTokenSource()).not.toThrow();
  });
});

describe("GCPMetadataTokenSource", () => {
  let server: http.Server;
  let metadataUrl: string;
  let handler: http.RequestListener;

  beforeAll((done) => {
    server = http.createServer((req, res) => handler(req, res));
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (address && typeof address === "object") {
        metadataUrl = `http://127.0.0.1:${address.port}`;
      }
      done();
    });
  });

  afterAll((done) => {
    server.close(() => done());
  });

  it("requires an audience", () => {
    expect(() => new GCPMetadataTokenSource({ audience: "  " })).toThrow(
      WorkloadIdentityConfigurationError,
    );
  });

  it("sends the documented request shape and returns the trimmed token", async () => {
    let seenUrl = "";
    let seenFlavor: string | undefined;
    handler = (req, res) => {
      seenUrl = req.url ?? "";
      seenFlavor = req.headers["metadata-flavor"] as string;
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end("gcp-identity-token\n");
    };

    const source = new GCPMetadataTokenSource({
      audience: "https://zone.example.com",
      metadataUrl,
    });

    await expect(source.identityToken()).resolves.toBe("gcp-identity-token");

    const url = new URL(seenUrl, metadataUrl);
    expect(url.pathname).toBe("/computeMetadata/v1/instance/service-accounts/default/identity");
    expect(url.searchParams.get("audience")).toBe("https://zone.example.com");
    expect(url.searchParams.get("format")).toBe("full");
    expect(seenFlavor).toBe("Google");
  });

  it.each([
    ["non-200 status", (res: http.ServerResponse) => { res.writeHead(404); res.end("not found"); }],
    ["empty body", (res: http.ServerResponse) => { res.writeHead(200); res.end("  \n"); }],
  ])("throws a runtime error on %s", async (_name, respond) => {
    handler = (_req, res) => respond(res);

    const source = new GCPMetadataTokenSource({
      audience: "https://zone.example.com",
      metadataUrl,
    });

    try {
      await source.identityToken();
      fail("expected a runtime error");
    } catch (error) {
      expect(error).toBeInstanceOf(WorkloadIdentityRuntimeError);
      expect((error as WorkloadIdentityRuntimeError).source).toBe("gcp-metadata");
    }
  });

  it("throws a runtime error with the cause when unreachable", async () => {
    const source = new GCPMetadataTokenSource({
      audience: "https://zone.example.com",
      metadataUrl: "http://127.0.0.1:1",
      timeoutMs: 1000,
    });

    try {
      await source.identityToken();
      fail("expected a runtime error");
    } catch (error) {
      expect(error).toBeInstanceOf(WorkloadIdentityRuntimeError);
      expect((error as WorkloadIdentityRuntimeError).cause).toBeDefined();
    }
  });
});

describe("FlyTokenSource", () => {
  let server: http.Server;
  let socketPath: string;
  let handler: http.RequestListener;

  beforeAll((done) => {
    // A short base dir keeps the socket path under the platform limit.
    socketPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "fly-")), "api.sock");
    server = http.createServer((req, res) => handler(req, res));
    server.listen(socketPath, () => done());
  });

  afterAll((done) => {
    server.close(() => done());
  });

  it("sends the documented request shape and returns the trimmed token", async () => {
    let seenMethod: string | undefined;
    let seenUrl: string | undefined;
    let seenContentType: string | undefined;
    let seenBody = "";
    handler = (req, res) => {
      seenMethod = req.method;
      seenUrl = req.url;
      seenContentType = req.headers["content-type"];
      req.on("data", (chunk) => {
        seenBody += chunk;
      });
      req.on("end", () => {
        res.writeHead(200, { "Content-Type": "text/plain" });
        res.end("fly-oidc-token\n");
      });
    };

    const source = new FlyTokenSource({
      audience: "https://zone.example.com",
      socketPath,
    });

    await expect(source.identityToken()).resolves.toBe("fly-oidc-token");
    expect(seenMethod).toBe("POST");
    expect(seenUrl).toBe("/v1/tokens/oidc");
    expect(seenContentType).toBe("application/json");
    expect(seenBody).toBe('{"aud":"https://zone.example.com"}');
  });

  it("sends an empty JSON object without an audience", async () => {
    let seenBody = "";
    handler = (req, res) => {
      req.on("data", (chunk) => {
        seenBody += chunk;
      });
      req.on("end", () => {
        res.writeHead(200);
        res.end("fly-oidc-token");
      });
    };

    const source = new FlyTokenSource({ socketPath });

    await expect(source.identityToken()).resolves.toBe("fly-oidc-token");
    expect(seenBody).toBe("{}");
  });

  it("throws a runtime error on a non-200 status", async () => {
    handler = (_req, res) => {
      res.writeHead(404);
      res.end("machine not found");
    };

    const source = new FlyTokenSource({ socketPath });

    try {
      await source.identityToken();
      fail("expected a runtime error");
    } catch (error) {
      expect(error).toBeInstanceOf(WorkloadIdentityRuntimeError);
      expect((error as WorkloadIdentityRuntimeError).source).toBe("fly");
    }
  });

  it("throws a runtime error with the cause when the socket is missing", async () => {
    const source = new FlyTokenSource({ socketPath: "/no/such/api.sock" });

    try {
      await source.identityToken();
      fail("expected a runtime error");
    } catch (error) {
      expect(error).toBeInstanceOf(WorkloadIdentityRuntimeError);
      expect((error as WorkloadIdentityRuntimeError).cause).toBeDefined();
    }
  });
});
