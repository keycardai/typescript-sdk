import * as fs from "node:fs";
import * as http from "node:http";
import * as os from "node:os";
import * as path from "node:path";
import { jest } from "@jest/globals";
import {
  AgentError,
  AgentErrorCode,
  AgentResponseError,
  AgentTokenSource,
  NetworkError,
  isApplicationNotFound,
  isAuthorizationRequired,
  isDeclined,
  isPrompterUnavailable,
  isRateLimited,
  isUnavailable,
  resourceTransport,
} from "./agent.js";
import type { ResourceTokenSource } from "./agent.js";
import { ConfigurationError, HTTPError } from "./errors.js";

// Test names carry the spec's row numbers (specs/delegated-access/
// local-agent-token-source.md, Unit Tests and Integration Tests). Every unit
// row runs against a fake agent on a real Unix socket: the SDK has no
// injectable client for node:http, so row 17's setup is every row's setup.

const ISSUE_TOKEN_PATH = "/keycard.agent.v1.AgentService/IssueToken";
const RESOURCE = "https://api.example.com";

interface SeenRequest {
  method?: string;
  url?: string;
  headers: http.IncomingHttpHeaders;
  body: string;
}

interface Reply {
  status?: number;
  body: unknown;
}

interface FakeAgent {
  socketPath: string;
  requests: SeenRequest[];
  reply: (request: SeenRequest) => Reply;
  close(): Promise<void>;
}

const tempDirs: string[] = [];

function tempDir(prefix: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

async function startFakeAgent(socketPath?: string): Promise<FakeAgent> {
  const agent: FakeAgent = {
    socketPath: socketPath ?? path.join(tempDir("kca-"), "agent.sock"),
    requests: [],
    reply: () => ({ body: { token: "agent-token" } }),
    close: async () => {},
  };
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
    });
    req.on("end", () => {
      const seen = { method: req.method, url: req.url, headers: req.headers, body };
      agent.requests.push(seen);
      const reply = agent.reply(seen);
      const payload = typeof reply.body === "string" ? reply.body : JSON.stringify(reply.body);
      res.writeHead(reply.status ?? 200, { "Content-Type": "application/json" });
      res.end(payload);
    });
  });
  await new Promise<void>((resolve) => server.listen(agent.socketPath, resolve));
  agent.close = () => new Promise<void>((resolve) => server.close(() => resolve()));
  return agent;
}

async function rejection(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  throw new Error("expected a rejection");
}

let agents: FakeAgent[] = [];

async function fakeAgent(socketPath?: string): Promise<FakeAgent> {
  const agent = await startFakeAgent(socketPath);
  agents.push(agent);
  return agent;
}

afterEach(async () => {
  await Promise.all(agents.map((a) => a.close()));
  agents = [];
  for (const dir of tempDirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

describe("AgentTokenSource request", () => {
  it("1: sends one IssueToken POST with resource, scopes, and workload", async () => {
    const agent = await fakeAgent();
    const source = new AgentTokenSource({ socket: agent.socketPath, workload: "nightly-digest" });

    await source.resourceToken(RESOURCE, { scopes: ["read", "write"] });

    expect(agent.requests).toHaveLength(1);
    const [request] = agent.requests;
    expect(request.method).toBe("POST");
    expect(request.url).toBe(ISSUE_TOKEN_PATH);
    expect(request.headers["content-type"]).toBe("application/json");
    expect(request.headers["connect-protocol-version"]).toBe("1");
    expect(JSON.parse(request.body)).toStrictEqual({
      resource: RESOURCE,
      scopes: ["read", "write"],
      workload: "nightly-digest",
    });
  });

  it("1: sends an empty scopes list and an empty workload when unset", async () => {
    const agent = await fakeAgent();

    await new AgentTokenSource({ socket: agent.socketPath }).resourceToken(RESOURCE);

    expect(JSON.parse(agent.requests[0].body)).toStrictEqual({ resource: RESOURCE, scopes: [], workload: "" });
  });

  it("2: sends Keycard-Org and Keycard-Zone only when set", async () => {
    const agent = await fakeAgent();

    await new AgentTokenSource({ socket: agent.socketPath, org: "org_1", zone: "zone_1" }).resourceToken(RESOURCE);
    await new AgentTokenSource({ socket: agent.socketPath }).resourceToken(RESOURCE);

    expect(agent.requests[0].headers["keycard-org"]).toBe("org_1");
    expect(agent.requests[0].headers["keycard-zone"]).toBe("zone_1");
    expect(agent.requests[1].headers).not.toHaveProperty("keycard-org");
    expect(agent.requests[1].headers).not.toHaveProperty("keycard-zone");
  });

  it("3: sends appId only when set", async () => {
    const agent = await fakeAgent();

    await new AgentTokenSource({ socket: agent.socketPath, appId: "incident-digest" }).resourceToken(RESOURCE);
    await new AgentTokenSource({ socket: agent.socketPath }).resourceToken(RESOURCE);

    expect(JSON.parse(agent.requests[0].body).appId).toBe("incident-digest");
    expect(JSON.parse(agent.requests[1].body)).not.toHaveProperty("appId");
  });

  it("4: sends the resource byte for byte, unnormalized", async () => {
    const agent = await fakeAgent();
    const resource = "HTTPS://API.Example.COM:443/a/./b/../c";

    await new AgentTokenSource({ socket: agent.socketPath }).resourceToken(resource);

    expect(JSON.parse(agent.requests[0].body).resource).toBe(resource);
  });

  it("5: rejects an empty resource with a configuration error and sends nothing", async () => {
    const agent = await fakeAgent();

    const error = await rejection(new AgentTokenSource({ socket: agent.socketPath }).resourceToken(""));

    expect(error).toBeInstanceOf(ConfigurationError);
    expect(agent.requests).toHaveLength(0);
  });

  it("5: rejects an empty resource before resolving the socket", async () => {
    const error = await rejection(new AgentTokenSource({ env: {} }).resourceToken(""));

    expect(error).toBeInstanceOf(ConfigurationError);
    expect((error as Error).message).toContain("resource");
  });

  it("18: sends two requests for the same resource and scopes", async () => {
    const agent = await fakeAgent();
    const source = new AgentTokenSource({ socket: agent.socketPath });

    await source.resourceToken(RESOURCE, { scopes: ["a"] });
    await source.resourceToken(RESOURCE, { scopes: ["a"] });

    expect(agent.requests).toHaveLength(2);
  });

  it("a connection that fails mid-response is a network error", async () => {
    const socketPath = path.join(tempDir("kca-"), "agent.sock");
    const server = http.createServer((_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json", "Content-Length": "100" });
      res.write('{"token":');
      setTimeout(() => res.socket?.destroy(), 10);
    });
    await new Promise<void>((resolve) => server.listen(socketPath, resolve));

    const error = await rejection(new AgentTokenSource({ socket: socketPath }).resourceToken(RESOURCE));

    expect(error).toBeInstanceOf(NetworkError);
    expect((error as Error).message).toContain(socketPath);
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it("rejects with the signal's reason when aborted while the agent waits on a human", async () => {
    const socketPath = path.join(tempDir("kca-"), "agent.sock");
    const server = http.createServer(() => {
      // Never answers, like an agent waiting on an approval prompt.
    });
    await new Promise<void>((resolve) => server.listen(socketPath, resolve));
    const controller = new AbortController();
    const reason = new Error("caller gave up");

    const pending = new AgentTokenSource({ socket: socketPath }).resourceToken(RESOURCE, { signal: controller.signal });
    setTimeout(() => controller.abort(reason), 20);

    await expect(pending).rejects.toBe(reason);
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });
});

describe("AgentTokenSource socket resolution", () => {
  async function resolvedPath(source: AgentTokenSource): Promise<NetworkError> {
    const error = await rejection(source.resourceToken(RESOURCE));
    expect(error).toBeInstanceOf(NetworkError);
    return error as NetworkError;
  }

  it("6: dials socket over KEYCARD_SOCKET", async () => {
    const chosen = await fakeAgent();
    const other = await fakeAgent();

    await new AgentTokenSource({
      socket: chosen.socketPath,
      env: { KEYCARD_SOCKET: other.socketPath },
    }).resourceToken(RESOURCE);

    expect(chosen.requests).toHaveLength(1);
    expect(other.requests).toHaveLength(0);
  });

  it("7: dials KEYCARD_SOCKET from env, not from the process environment", async () => {
    const fromEnv = await fakeAgent();
    const fromProcess = await fakeAgent();
    const saved = process.env.KEYCARD_SOCKET;
    process.env.KEYCARD_SOCKET = fromProcess.socketPath;
    try {
      await new AgentTokenSource({ env: { KEYCARD_SOCKET: fromEnv.socketPath } }).resourceToken(RESOURCE);
    } finally {
      if (saved === undefined) delete process.env.KEYCARD_SOCKET;
      else process.env.KEYCARD_SOCKET = saved;
    }

    expect(fromEnv.requests).toHaveLength(1);
    expect(fromProcess.requests).toHaveLength(0);
  });

  it("7: reads the process environment when env is not given, on every call", async () => {
    const first = await fakeAgent();
    const second = await fakeAgent();
    const saved = process.env.KEYCARD_SOCKET;
    const source = new AgentTokenSource();
    try {
      process.env.KEYCARD_SOCKET = first.socketPath;
      await source.resourceToken(RESOURCE);
      process.env.KEYCARD_SOCKET = second.socketPath;
      await source.resourceToken(RESOURCE);
    } finally {
      if (saved === undefined) delete process.env.KEYCARD_SOCKET;
      else process.env.KEYCARD_SOCKET = saved;
    }

    expect(first.requests).toHaveLength(1);
    expect(second.requests).toHaveLength(1);
  });

  const unixOnly = process.platform === "win32" ? describe.skip : describe;

  unixOnly("default socket", () => {
    it.each([
      ["8", { KEYCARD_SOCKET: "", HOME: "/h" }, "/h/.local/state/keycard/run/agent.sock"],
      ["9", { HOME: "/h" }, "/h/.local/state/keycard/run/agent.sock"],
      ["10", { HOME: "/h", KEYCARD_HOME: "/k" }, "/k/.local/state/keycard/run/agent.sock"],
      ["11", { HOME: "/h", XDG_STATE_HOME: "/s" }, "/s/keycard/run/agent.sock"],
      ["12", { HOME: "/h", XDG_STATE_HOME: "/s", XDG_RUNTIME_DIR: "/r" }, "/r/keycard/agent.sock"],
      [
        "13",
        { HOME: "/h", XDG_STATE_HOME: "/s", XDG_RUNTIME_DIR: "/r", KEYCARD_AGENT_DIR: "/a" },
        "/a/agent.sock",
      ],
    ])("%s: resolves %j to %s", async (_row, env, expected) => {
      const error = await resolvedPath(new AgentTokenSource({ env }));

      expect(error.message).toContain(`${expected} (the keycard agent daemon's default socket`);
    });

    it("14: does not read keycard.toml", async () => {
      const project = tempDir("kcp-");
      fs.writeFileSync(path.join(project, "keycard.toml"), '[home]\ndir = "/elsewhere"\n\n[agent]\nDir = "/agentdir"\n');
      const cwd = process.cwd();
      process.chdir(project);
      try {
        const error = await resolvedPath(new AgentTokenSource({ env: { HOME: "/h" } }));

        expect(error.message).toContain("/h/.local/state/keycard/run/agent.sock");
      } finally {
        process.chdir(cwd);
      }
    });

    it("15: an empty env is a configuration error naming KEYCARD_SOCKET and HOME", async () => {
      const error = await rejection(new AgentTokenSource({ env: {} }).resourceToken(RESOURCE));

      expect(error).toBeInstanceOf(ConfigurationError);
      expect((error as Error).message).toContain("KEYCARD_SOCKET");
      expect((error as Error).message).toContain("HOME");
    });

    it("16: a failed connect names the path, suggests keycard agent start, and creates nothing", async () => {
      const home = tempDir("kch-");

      const error = await resolvedPath(new AgentTokenSource({ env: { HOME: home } }));

      expect(error.message).toContain(path.join(home, ".local/state/keycard/run/agent.sock"));
      expect(error.message).toContain("keycard agent start");
      expect(error.retryable).toBe(true);
      expect(error.cause).toBeDefined();
      expect(fs.readdirSync(home)).toHaveLength(0);
    });
  });

  it("names the rule that chose the socket in a network error, without suggesting the daemon", async () => {
    const missing = path.join(tempDir("kcm-"), "run-abc.sock");

    const fromOption = await resolvedPath(new AgentTokenSource({ socket: missing }));
    const fromEnv = await resolvedPath(new AgentTokenSource({ env: { KEYCARD_SOCKET: missing } }));

    expect(fromOption.message).toContain(`${missing} (from the socket option)`);
    expect(fromEnv.message).toContain(`${missing} (from KEYCARD_SOCKET)`);
    expect(fromOption.message).not.toContain("keycard agent start");
  });

  it("is a configuration error on Windows once the default socket is needed", async () => {
    const platform = Object.getOwnPropertyDescriptor(process, "platform")!;
    Object.defineProperty(process, "platform", { value: "win32" });
    try {
      const error = await rejection(new AgentTokenSource({ env: { HOME: "/h" } }).resourceToken(RESOURCE));

      expect(error).toBeInstanceOf(ConfigurationError);
      expect((error as Error).message).toContain("KEYCARD_SOCKET");
    } finally {
      Object.defineProperty(process, "platform", platform);
    }
  });

  it("is inert at construction", () => {
    expect(() => new AgentTokenSource({ env: {} })).not.toThrow();
  });
});

describe("AgentTokenSource response", () => {
  async function mint(reply: Reply, options?: { clock?: { now(): number }; scopes?: string[] }) {
    const agent = await fakeAgent();
    agent.reply = () => reply;
    return new AgentTokenSource({ socket: agent.socketPath, clock: options?.clock }).resourceToken(RESOURCE, {
      scopes: options?.scopes,
    });
  }

  it("17: returns the token from a fake agent behind a real Unix socket", async () => {
    const token = await mint({ body: { token: "agent-token" } });

    expect(token.accessToken).toBe("agent-token");
    expect(token.tokenType).toBe("Bearer");
  });

  it("ignores unknown response keys", async () => {
    const token = await mint({ body: { token: "agent-token", future: { field: 1 } } });

    expect(token.accessToken).toBe("agent-token");
  });

  it("24: no expiresAt leaves expiresIn undefined", async () => {
    const token = await mint({ body: { token: "t" } });

    expect(token.expiresIn).toBeUndefined();
  });

  it("25: an expiresAt in the past gives expiresIn 0", async () => {
    const token = await mint({ body: { token: "t", expiresAt: "2001-01-01T00:00:00Z" } });

    expect(token.expiresIn).toBe(0);
  });

  it.each([
    ["2026-11-17T12:00:30.123456789Z", "2026-11-17T12:00:00.500Z", 29],
    ["2026-11-17T12:00:30.999999999Z", "2026-11-17T12:00:00Z", 30],
    ["2026-11-17T13:00:30.000000001+01:00", "2026-11-17T12:00:00Z", 30],
  ])("26: parses %s against the injected clock at %s", async (expiresAt, now, expected) => {
    const token = await mint({ body: { token: "t", expiresAt } }, { clock: { now: () => Date.parse(now) } });

    expect(token.expiresIn).toBe(expected);
  });

  it.each(["tomorrow", "2026-11-17", "2026-11-17T12:00:00", "2026-11-17T12:00:00.1234567890Z", "2026-02-30T00:00:00Z", 1700000000])(
    "rejects an unparseable expiresAt %p",
    async (expiresAt) => {
      const error = await rejection(mint({ body: { token: "t", expiresAt } }));

      expect(error).toBeInstanceOf(AgentResponseError);
    },
  );

  it("27: reports the agent's scopes, not the request's", async () => {
    const token = await mint({ body: { token: "t", scopes: ["a", "b"] } }, { scopes: ["a"] });

    expect(token.scope).toStrictEqual(["a", "b"]);
  });

  it.each([
    ["absent", {}],
    ["empty", { scopes: [] }],
  ])("28: %s scopes leave scope absent, not the request's", async (_name, extra) => {
    const token = await mint({ body: { token: "t", ...extra } }, { scopes: ["a"] });

    expect(token).not.toHaveProperty("scope");
  });

  const predicates = {
    permission_denied: isDeclined,
    resource_exhausted: isRateLimited,
    failed_precondition: isPrompterUnavailable,
    unauthenticated: isAuthorizationRequired,
    not_found: isApplicationNotFound,
    unavailable: isUnavailable,
  };

  it.each(Object.values(AgentErrorCode))("29: a Connect error %s is an AgentError matching only its predicate", async (code) => {
    const error = await rejection(mint({ status: 403, body: { code, message: `agent says ${code}` } }));

    expect(error).toBeInstanceOf(AgentError);
    expect((error as AgentError).code).toBe(code);
    expect((error as AgentError).message).toBe(`agent says ${code}`);
    for (const [predicateCode, predicate] of Object.entries(predicates)) {
      expect([predicateCode, predicate(error)]).toStrictEqual([predicateCode, predicateCode === code]);
    }
  });

  it("30: the predicates match an agent error on the cause chain", () => {
    const agentError = new AgentError("permission_denied", "declined");
    const wrapped = Object.assign(new Error("minting failed"), {
      cause: Object.assign(new Error("inner"), { cause: agentError }),
    });

    expect(isDeclined(wrapped)).toBe(true);
    expect(isApplicationNotFound(wrapped)).toBe(false);
  });

  it("30: the predicates are false for other errors", () => {
    const cyclic: Error & { cause?: unknown } = new Error("cyclic");
    cyclic.cause = cyclic;

    expect(isDeclined(new Error("x"))).toBe(false);
    expect(isDeclined("permission_denied")).toBe(false);
    expect(isDeclined(cyclic)).toBe(false);
  });

  it.each([
    ["non-JSON", "upstream connect error"],
    ["JSON without code", { error: "boom" }],
    ["empty code", { code: "", message: "x" }],
  ])("31: a non-200 %s body is an HTTPError carrying the status", async (_name, body) => {
    const error = await rejection(mint({ status: 502, body }));

    expect(error).toBeInstanceOf(HTTPError);
    expect(error).not.toBeInstanceOf(AgentError);
    expect((error as HTTPError).status).toBe(502);
  });

  it("reads a bounded prefix of an error body", async () => {
    const error = await rejection(mint({ status: 500, body: "x".repeat(1024 * 1024) }));

    expect(error).toBeInstanceOf(HTTPError);
  });

  it.each([
    ["an empty token", { token: "" }],
    ["a missing token", {}],
    ["a non-string token", { token: 42 }],
    ["a non-JSON body", "<html>"],
    ["a JSON array", "[]"],
  ])("32: a 200 with %s is an AgentResponseError", async (_name, body) => {
    const error = await rejection(mint({ body }));

    expect(error).toBeInstanceOf(AgentResponseError);
    expect((error as AgentResponseError).retryable).toBe(false);
  });

  it.each(["abc\r\ndef", "abc\x00", "abc\x7f", "\tabc"])("33: a token with a control character %j is rejected without echoing it", async (token) => {
    const error = await rejection(mint({ body: { token } }));

    expect(error).toBeInstanceOf(AgentResponseError);
    expect((error as Error).message).not.toContain(token);
  });

  it.each(Object.values(AgentErrorCode))("34: retryable for %s", (code) => {
    expect(new AgentError(code, "").retryable).toBe(["resource_exhausted", "unavailable"].includes(code));
  });
});

describe("resourceTransport", () => {
  function stubSource(token = "resource-token"): ResourceTokenSource & { calls: unknown[][] } {
    const calls: unknown[][] = [];
    return {
      calls,
      async resourceToken(resource, options) {
        calls.push([resource, options?.scopes]);
        return { accessToken: token, tokenType: "Bearer" };
      },
    };
  }

  function recordingFetch() {
    return jest.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => new Response("ok"));
  }

  it("35: sets Authorization: Bearer <token> from the source for the bound resource and scopes", async () => {
    const source = stubSource();
    const fetchMock = recordingFetch();
    const send = resourceTransport({ source, resource: RESOURCE, scopes: ["read"], fetch: fetchMock as typeof fetch });

    await send("https://api.example.com/v1/things");

    expect(source.calls).toStrictEqual([[RESOURCE, ["read"]]]);
    const [input, init] = fetchMock.mock.calls[0];
    expect(input).toBe("https://api.example.com/v1/things");
    expect(new Headers(init?.headers).get("authorization")).toBe("Bearer resource-token");
  });

  it("35: replaces an existing Authorization header and keeps the others", async () => {
    const fetchMock = recordingFetch();
    const send = resourceTransport({ source: stubSource(), resource: RESOURCE, fetch: fetchMock as typeof fetch });

    await send("https://api.example.com", { headers: { Authorization: "Bearer old", Accept: "application/json" } });

    const headers = new Headers(fetchMock.mock.calls[0][1]?.headers);
    expect(headers.get("authorization")).toBe("Bearer resource-token");
    expect(headers.get("accept")).toBe("application/json");
  });

  it("36: a declined source error reaches the caller and no request is sent", async () => {
    const declined = new AgentError("permission_denied", "the human declined");
    const fetchMock = recordingFetch();
    const send = resourceTransport({
      source: { resourceToken: async () => Promise.reject(declined) },
      resource: RESOURCE,
      fetch: fetchMock as typeof fetch,
    });

    const error = await rejection(send("https://api.example.com"));

    expect(error).toBe(declined);
    expect(isDeclined(error)).toBe(true);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("37: requires a source, then a resource", () => {
    expect(() => resourceTransport({ resource: RESOURCE } as never)).toThrow(ConfigurationError);
    expect(() => resourceTransport({ source: stubSource(), resource: "" })).toThrow(ConfigurationError);
  });

  it("38: leaves the caller's Request and init unchanged", async () => {
    const fetchMock = recordingFetch();
    const send = resourceTransport({ source: stubSource(), resource: RESOURCE, fetch: fetchMock as typeof fetch });
    const request = new Request("https://api.example.com", { headers: { Authorization: "Bearer old", "X-Trace": "1" } });
    const initHeaders = { "X-Init": "1" };
    const init: RequestInit = { method: "GET", headers: initHeaders };

    await send(request);
    await send("https://api.example.com", init);

    expect(request.headers.get("authorization")).toBe("Bearer old");
    expect(new Headers(fetchMock.mock.calls[0][1]?.headers).get("x-trace")).toBe("1");
    expect(new Headers(fetchMock.mock.calls[0][1]?.headers).get("authorization")).toBe("Bearer resource-token");
    expect(fetchMock.mock.calls[0][0]).toBe(request);
    expect(init).toStrictEqual({ method: "GET", headers: { "X-Init": "1" } });
    expect(init.headers).toBe(initHeaders);
  });

  it("uses the global fetch by default", async () => {
    const originalFetch = globalThis.fetch;
    const fetchMock = recordingFetch();
    globalThis.fetch = fetchMock as typeof fetch;
    try {
      await resourceTransport({ source: stubSource(), resource: RESOURCE })("https://api.example.com");
    } finally {
      globalThis.fetch = originalFetch;
    }

    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});

// The SDK-observable half of the spec's Integration Tests, against a fake
// agent. What only a live agent and zone can show (the prompt, the agent's
// cache, the token's claims and signature) is left to the hand-run example.
describe("integration against a fake agent", () => {
  let resourceServer: http.Server;
  let resourceUrl: string;
  let seenAuthorization: (string | undefined)[];

  beforeEach(async () => {
    seenAuthorization = [];
    resourceServer = http.createServer((req, res) => {
      seenAuthorization.push(req.headers.authorization);
      res.writeHead(req.headers.authorization === "Bearer agent-token" ? 200 : 401);
      res.end();
    });
    await new Promise<void>((resolve) => resourceServer.listen(0, "127.0.0.1", resolve));
    const address = resourceServer.address() as { port: number };
    resourceUrl = `http://127.0.0.1:${address.port}/`;
  });

  afterEach(async () => {
    await new Promise<void>((resolve) => resourceServer.close(() => resolve()));
  });

  it("1: mints with no application credential in the process", async () => {
    const agent = await fakeAgent();

    const token = await new AgentTokenSource({ socket: agent.socketPath }).resourceToken(RESOURCE);

    expect(token.accessToken).toBe("agent-token");
    expect(agent.requests[0].headers).not.toHaveProperty("authorization");
  });

  it("2, 3: sends through a resource transport, reaching the agent on every call", async () => {
    const agent = await fakeAgent();
    const source = new AgentTokenSource({ socket: agent.socketPath });

    await source.resourceToken(RESOURCE);
    await source.resourceToken(RESOURCE);
    const response = await resourceTransport({ source, resource: RESOURCE })(resourceUrl);

    expect(response.status).toBe(200);
    expect(seenAuthorization).toStrictEqual(["Bearer agent-token"]);
    expect(agent.requests).toHaveLength(3);
  });

  it("4: a declined prompt is isDeclined", async () => {
    const agent = await fakeAgent();
    agent.reply = () => ({ status: 403, body: { code: "permission_denied", message: "declined" } });

    const error = await rejection(new AgentTokenSource({ socket: agent.socketPath }).resourceToken(RESOURCE, { scopes: ["new"] }));

    expect(isDeclined(error)).toBe(true);
  });

  it("5: an unknown appId is isApplicationNotFound", async () => {
    const agent = await fakeAgent();
    agent.reply = () => ({ status: 404, body: { code: "not_found", message: "no application nope" } });

    const error = await rejection(new AgentTokenSource({ socket: agent.socketPath, appId: "nope" }).resourceToken(RESOURCE));

    expect(isApplicationNotFound(error)).toBe(true);
  });

  it("6: declares appId to the agent", async () => {
    const agent = await fakeAgent();

    await new AgentTokenSource({ socket: agent.socketPath, appId: "urn:app:zazu" }).resourceToken(RESOURCE);

    expect(JSON.parse(agent.requests[0].body).appId).toBe("urn:app:zazu");
  });

  const unixOnly = process.platform === "win32" ? describe.skip : describe;

  unixOnly("default socket", () => {
    // The socket path has to fit sockaddr_un (104 bytes on macOS).
    function home(): string {
      return fs.mkdtempSync(path.join(os.tmpdir().length > 40 ? "/tmp" : os.tmpdir(), "kc-"));
    }

    it("7: reaches a daemon at the default socket under HOME, with org and zone", async () => {
      const dir = home();
      tempDirs.push(dir);
      const runDir = path.join(dir, ".local/state/keycard/run");
      fs.mkdirSync(runDir, { recursive: true });
      const agent = await fakeAgent(path.join(runDir, "agent.sock"));

      const token = await new AgentTokenSource({ env: { HOME: dir }, org: "org_1", zone: "zone_1" }).resourceToken(RESOURCE);

      expect(token.accessToken).toBe("agent-token");
      expect(agent.requests[0].headers["keycard-org"]).toBe("org_1");
      expect(agent.requests[0].headers["keycard-zone"]).toBe("zone_1");
    });

    it("8: a stopped daemon is a network error naming the default socket", async () => {
      const dir = home();
      tempDirs.push(dir);

      const error = await rejection(new AgentTokenSource({ env: { HOME: dir }, org: "org_1", zone: "zone_1" }).resourceToken(RESOURCE));

      expect(error).toBeInstanceOf(NetworkError);
      expect((error as Error).message).toContain(path.join(dir, ".local/state/keycard/run/agent.sock"));
      expect((error as Error).message).toContain("keycard agent start");
    });
  });
});
