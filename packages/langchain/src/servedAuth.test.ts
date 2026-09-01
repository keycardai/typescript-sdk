/**
 * Inbound authentication and ownership for an agent served by LangGraph JS.
 *
 * Hermetic: bearer verification goes through the injectable seam, so no zone
 * and no network are involved. Authorization events run through the JS
 * server's own `authorize`, user normalization and owner filter matcher
 * (`@langchain/langgraph-api/auth`), so the assertions reflect what a
 * deployment does rather than a local reimplementation of the dispatch rules.
 */

import { beforeAll, describe, expect, it } from "@jest/globals";
import {
  authenticate as serverAuthenticate,
  authorize as serverAuthorize,
  isAuthMatching,
  registerAuth,
} from "@langchain/langgraph-api/auth";
import { ToolMessage } from "@langchain/core/messages";
import { tool } from "@langchain/core/tools";
import { Auth, HTTPException } from "@langchain/langgraph-sdk/auth";
import { createAgent } from "langchain";
import { z } from "zod";
import { getAccessContext } from "./accessStore.js";
import { keycardGrantMiddleware } from "./middleware.js";
import {
  installOwnerAuthorization,
  zoneAuthenticator,
  type VerifiedCaller,
  type VerifyToken,
  type ZoneAuthUser,
} from "./servedAuth.js";
import { callerFromRuntime } from "./servedCaller.js";
import { FakeToolCallingModel, recordingZoneClient } from "./testUtils.js";

const ZONE = "https://zone.example.test";
const RESOURCE = "https://agent.example.test";
const METADATA_URL = `${ZONE}/.well-known/oauth-authorization-server`;
const ADA = "ada@example.test";
const GRACE = "grace@example.test";
const CALLERS: Record<string, string> = { "token-a": ADA, "token-b": GRACE };

const stubVerify: VerifyToken = async (token) => {
  const identity = CALLERS[token];
  if (identity === undefined) throw new Error("token is not zone-issued");
  return { identity, scopes: ["openid", "email"] };
};

function authenticator(verify: VerifyToken = stubVerify) {
  return zoneAuthenticator({ zoneUrl: ZONE, resource: RESOURCE, verify });
}

function request(authorization?: string): Request {
  const headers = new Headers({ "content-type": "application/json" });
  if (authorization !== undefined) headers.set("authorization", authorization);
  return new Request("https://agent.example.test/threads", {
    method: "POST",
    headers,
  });
}

/** The thrown value, so a rejection can be inspected rather than just caught. */
async function rejection(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (thrown) {
    return thrown;
  }
  throw new Error("expected the call to reject");
}

/** The `WWW-Authenticate` value the framework would put on the response. */
function challengeOf(thrown: unknown): string {
  const headers = new Headers((thrown as HTTPException).headers);
  const challenge = headers.get("WWW-Authenticate");
  expect(challenge).not.toBeNull();
  return challenge!;
}

describe("zoneAuthenticator", () => {
  it("delivers the identity and the caller's raw bearer", async () => {
    const user = await authenticator()(request("Bearer token-a"));
    expect(user.identity).toBe(ADA);
    expect(user.display_name).toBe(ADA);
    expect(user.subject_token).toBe("token-a");
    expect(user.permissions).toEqual(["openid", "email"]);
  });

  it("challenges a request with no bearer", async () => {
    const thrown = await rejection(authenticator()(request()));
    expect((thrown as HTTPException).status).toBe(401);
    const challenge = challengeOf(thrown);
    expect(challenge.startsWith("Bearer ")).toBe(true);
    expect(challenge).toContain('error="invalid_request"');
    expect(challenge).toContain(`authorization_uri="${METADATA_URL}"`);
  });

  it("challenges a bearer the verifier rejects", async () => {
    const thrown = await rejection(authenticator()(request("Bearer forged")));
    expect((thrown as HTTPException).status).toBe(401);
    const challenge = challengeOf(thrown);
    expect(challenge).toContain('error="invalid_token"');
    expect(challenge).toContain(METADATA_URL);
  });

  it.each([
    ["a non-bearer scheme", "Basic YWRhOm9wZW4="],
    ["a scheme with no token", "Bearer"],
    ["an empty header", ""],
  ])("challenges %s", async (_name, authorization) => {
    const thrown = await rejection(authenticator()(request(authorization)));
    expect((thrown as HTTPException).status).toBe(401);
  });

  it("turns an exploding verifier into a challenge, not a 500", async () => {
    const explode: VerifyToken = async () => {
      throw new RangeError("the verifier fell over");
    };
    const thrown = await rejection(authenticator(explode)(request("Bearer token-a")));
    expect((thrown as HTTPException).status).toBe(401);
    expect(challengeOf(thrown)).toContain("RangeError");
  });

  it("requires a zone and a resource", () => {
    expect(() => zoneAuthenticator({ zoneUrl: "", resource: RESOURCE })).toThrow();
    expect(() => zoneAuthenticator({ zoneUrl: ZONE, resource: "" })).toThrow();
  });

  it("names the zone metadata URL without a doubled slash", async () => {
    const hook = zoneAuthenticator({
      zoneUrl: `${ZONE}/`,
      resource: RESOURCE,
      verify: stubVerify,
    });
    const thrown = await rejection(hook(request()));
    expect(challengeOf(thrown)).toContain(`authorization_uri="${METADATA_URL}"`);
  });
});

type Metadata = Record<string, unknown>;
type Filters = Record<string, unknown> | undefined;

/**
 * Register the package's auth object with the server the way a deployment
 * does, by pointing the loader at a module that exports it.
 *
 * Everything below then runs through the server's own `authenticate` and
 * `authorize`, so handler precedence, user normalization and rejection
 * conversion are the deployment's behavior and not this file's.
 */
beforeAll(async () => {
  (globalThis as { __keycardServedAuth?: unknown }).__keycardServedAuth =
    installOwnerAuthorization(new Auth().authenticate(authenticator()));
  await registerAuth(
    { path: "./src/__fixtures__/servedAuthFixture.mjs:default", disable_studio_auth: true },
    { cwd: process.cwd() },
  );
});

/**
 * The user object as the server hands it to a run and to authorization
 * handlers, built by the server's own normalization of the hook's return.
 */
async function servedUser(authorization: string): Promise<ZoneAuthUser> {
  const result = await serverAuthenticate(request(authorization));
  return result!.user as unknown as ZoneAuthUser;
}

/**
 * Run one authorization event the way the server runs it.
 *
 * `authorize` resolves the handler by the framework's own precedence
 * (`resource:action`, then `resource`, then `*:action`, then `*`) and hands the
 * handler the payload it mutates, which is how namespace scoping takes effect.
 */
async function dispatch(
  user: { identity: string; [key: string]: unknown },
  resource: string,
  action: string,
  value: Record<string, unknown>,
): Promise<Filters> {
  const result = await serverAuthorize({
    resource,
    action,
    value,
    context: { user, scopes: [] },
  } as never);
  return result.filters as Filters;
}

function user(identity: string) {
  return { identity, display_name: identity, permissions: [], is_authenticated: true };
}

const STUDIO_USER = {
  kind: "StudioUser" as const,
  identity: "langgraph-studio-user",
  display_name: "langgraph-studio-user",
  permissions: [],
  is_authenticated: true,
};

describe("installOwnerAuthorization", () => {
  it("stamps the owner on thread creation from the verified identity", async () => {
    const value: { thread_id: string; metadata: Metadata | null } = {
      thread_id: "t-1",
      metadata: null,
    };
    const filters = await dispatch(user(ADA), "threads", "create", value);
    expect(value.metadata).toEqual({ owner: ADA });
    expect(filters).toEqual({ owner: ADA });
  });

  it("overwrites an owner supplied in the request body", async () => {
    const value = { thread_id: "t-1", metadata: { owner: GRACE } };
    const filters = await dispatch(user(ADA), "threads", "create", value);
    expect(value.metadata.owner).toBe(ADA);
    expect(filters).toEqual({ owner: ADA });
  });

  it("filters a cross-owner thread read", async () => {
    const thread: { thread_id: string; metadata: Metadata } = {
      thread_id: "t-1",
      metadata: {},
    };
    await dispatch(user(ADA), "threads", "create", thread);
    const own = await dispatch(user(ADA), "threads", "read", { thread_id: "t-1" });
    const other = await dispatch(user(GRACE), "threads", "read", { thread_id: "t-1" });
    expect(isAuthMatching(thread.metadata, own as never)).toBe(true);
    expect(isAuthMatching(thread.metadata, other as never)).toBe(false);
  });

  it("filters a cross-owner resume", async () => {
    const thread: { thread_id: string; metadata: Metadata } = {
      thread_id: "t-1",
      metadata: {},
    };
    await dispatch(user(ADA), "threads", "create", thread);
    const resume = { thread_id: "t-1", assistant_id: "agent", metadata: {} };
    const filters = await dispatch(user(GRACE), "threads", "create_run", resume);
    expect(isAuthMatching(thread.metadata, filters as never)).toBe(false);
    expect(resume.metadata).toEqual({ owner: GRACE });
  });

  it("scopes store items to the caller with a store-safe segment", async () => {
    const put: { namespace: string[]; key: string; value: Metadata } = {
      namespace: ["memories"],
      key: "k",
      value: {},
    };
    const filters = await dispatch(user(ADA), "store", "put", put);
    const segment = put.namespace[0]!;
    expect(put.namespace).toEqual([segment, "memories"]);
    // The store rejects namespace labels containing periods, so the owner
    // segment must never be the raw email identity.
    expect(segment).not.toContain(".");
    expect(segment).not.toBe(ADA);
    expect(filters).toEqual({ namespace: { $contains: segment } });
  });

  it("gives each caller a distinct store segment", async () => {
    const adaPut = { namespace: ["memories"], key: "k", value: {} };
    const gracePut = { namespace: ["memories"], key: "k", value: {} };
    await dispatch(user(ADA), "store", "put", adaPut);
    await dispatch(user(GRACE), "store", "put", gracePut);
    expect(adaPut.namespace[0]).not.toBe(gracePut.namespace[0]);
  });

  it.each(["get", "search", "delete", "list_namespaces"])(
    "scopes store:%s to the caller",
    async (action) => {
      const value: { namespace?: string[] } = { namespace: ["memories"] };
      const filters = await dispatch(user(ADA), "store", action, value);
      expect(value.namespace).toEqual([expect.any(String), "memories"]);
      expect(filters).toEqual({ namespace: { $contains: value.namespace![0] } });
    },
  );

  it("scopes a namespace listing that carries no prefix at all", async () => {
    const listing: { namespace?: string[] } = {};
    const filters = await dispatch(user(ADA), "store", "list_namespaces", listing);
    expect(listing.namespace).toHaveLength(1);
    expect(listing.namespace![0]).not.toContain(".");
    expect(filters).toEqual({ namespace: { $contains: listing.namespace![0] } });
  });

  it.each([
    ["crons", "create"],
    ["assistants", "create"],
    ["assistants", "update"],
    ["assistants", "delete"],
    ["crons", "search"],
  ])("denies the unmatched pair %s:%s", async (resource, action) => {
    const thrown = await rejection(dispatch(user(ADA), resource, action, {}));
    expect((thrown as { status: number }).status).toBe(403);
  });

  it("leaves assistant reads and searches open to authenticated callers", async () => {
    expect(
      await dispatch(user(ADA), "assistants", "read", { assistant_id: "a" }),
    ).toBeUndefined();
    expect(await dispatch(user(ADA), "assistants", "search", {})).toBeUndefined();
  });

  it.each([
    ["threads", "create"],
    ["threads", "read"],
    ["store", "put"],
    ["assistants", "search"],
  ])("denies a Studio user on %s:%s", async (resource, action) => {
    const thrown = await rejection(
      dispatch(STUDIO_USER, resource, action, { namespace: ["x"] }),
    );
    expect((thrown as { status: number }).status).toBe(403);
  });
});

interface ServedRun {
  /** The tool output, which carries the token the tool actually received. */
  output: string;
  /** Subject tokens the zone client was asked to exchange. */
  exchanged: string[];
}

/**
 * Invoke an agent configured the way a served deployment configures it, with
 * the verified user on the run config rather than in caller-supplied context.
 */
async function servedRun(
  config: Record<string, unknown>,
  contextIdentity?: Record<string, unknown>,
): Promise<ServedRun> {
  const client = recordingZoneClient();
  const readCalendar = tool(
    async () => {
      const access = getAccessContext();
      if (access.hasError()) return `GLOBAL_ERROR: ${access.getError()?.errorCode}`;
      return `TOKEN: ${access.access(RESOURCE).accessToken}`;
    },
    { name: "read_calendar", description: "read", schema: z.object({}) },
  );

  const agent = createAgent({
    model: new FakeToolCallingModel("read_calendar"),
    tools: [readCalendar],
    middleware: [
      keycardGrantMiddleware({
        resources: [RESOURCE],
        client,
        identitySource: "auth_user",
        interruptOnAuth: false,
      }),
    ],
  });

  const result = (await agent.invoke(
    { messages: [{ role: "user", content: "go" }] },
    { ...config, ...(contextIdentity ? { context: contextIdentity } : {}) },
  )) as { messages: { content: unknown }[] };

  const toolMessages = result.messages.filter(
    (message): message is ToolMessage => message instanceof ToolMessage,
  );
  return {
    output: String(toolMessages[toolMessages.length - 1]!.content),
    exchanged: client.exchanges.map((exchange) => exchange.subjectToken ?? ""),
  };
}

/** The run config a server builds from an authenticated request. */
async function runConfig(authorization: string): Promise<Record<string, unknown>> {
  return {
    configurable: { langgraph_auth_user: await servedUser(authorization) },
  };
}

describe("middleware identitySource auth_user", () => {
  it("exchanges under the verified caller's own bearer", async () => {
    const config = await runConfig("Bearer token-a");
    const run = await servedRun(config);
    expect(run.output).toContain("TOKEN:");
    expect(run.exchanged).toEqual(["token-a"]);
    expect(callerFromRuntime(config)!.identity).toBe(ADA);
  });

  it("keeps two callers apart", async () => {
    // The single-slot token store this mode replaces made the last caller win.
    const first = await servedRun(await runConfig("Bearer token-a"));
    const second = await servedRun(await runConfig("Bearer token-b"));
    expect([first.exchanged[0], second.exchanged[0]]).toEqual(["token-a", "token-b"]);
  });

  it("ignores an identity supplied in caller context", async () => {
    // Runtime context comes from the request body, so it cannot name an identity.
    const run = await servedRun({}, { subjectToken: "forged-token" });
    expect(run.output).toContain("GLOBAL_ERROR");
    expect(run.exchanged).toEqual([]);
  });

  it("rejects a second identity source", () => {
    expect(() =>
      keycardGrantMiddleware({
        zoneUrl: ZONE,
        resources: [RESOURCE],
        identitySource: "auth_user",
        fallbackIdentity: { asSelf: true },
      }),
    ).toThrow(/fallbackIdentity/);
  });

  it("rejects an unknown identity source", () => {
    expect(() =>
      keycardGrantMiddleware({
        zoneUrl: ZONE,
        resources: [RESOURCE],
        identitySource: "whatever" as never,
      }),
    ).toThrow(/identitySource/);
  });
});

describe("callerFromRuntime", () => {
  it.each([
    ["nothing", undefined],
    ["a runtime with no configurable", {}],
    ["a configurable with no user", { configurable: {} }],
    ["a user with neither field", { configurable: { langgraph_auth_user: {} } }],
    [
      "a user with no token",
      { configurable: { langgraph_auth_user: { identity: ADA } } },
    ],
    [
      "a user with no identity",
      { configurable: { langgraph_auth_user: { subject_token: "t" } } },
    ],
  ])("reads no caller from %s", (_name, runtime) => {
    expect(callerFromRuntime(runtime)).toBeNull();
  });

  it("reads the caller the server put on the run", () => {
    const runtime = {
      configurable: {
        langgraph_auth_user: { identity: ADA, subject_token: "token-a" },
      },
    };
    expect(callerFromRuntime(runtime)).toEqual({
      identity: ADA,
      subjectToken: "token-a",
    });
  });
});

describe("the verified caller survives the server's normalization", () => {
  it("keeps the subject token as an extra field on the user", async () => {
    const normalized = await servedUser("Bearer token-b");
    expect(normalized.identity).toBe(GRACE);
    expect(normalized.subject_token).toBe("token-b");
    expect(normalized.permissions).toEqual(["openid", "email"]);
  });

  it("turns a hook rejection into a response that keeps the challenge", async () => {
    const auth = new Auth().authenticate(authenticator());
    const handlers = (auth as unknown as AuthInternals)["~handlerCache"];
    const thrown = (await rejection(
      serverAuthenticate.call({ "~handlerCache": handlers }, request()),
    )) as { status: number; getResponse: () => Response };
    expect(thrown.status).toBe(401);
    const response = thrown.getResponse();
    expect(response.status).toBe(401);
    expect(response.headers.get("WWW-Authenticate")).toContain(METADATA_URL);
  });
});

/** A verified caller shape used only to keep the seam's type in the suite. */
const _shape: VerifiedCaller = { identity: ADA, scopes: [] };
void _shape;
