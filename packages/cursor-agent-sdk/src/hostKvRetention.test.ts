import { afterEach, describe, expect, it, jest } from "@jest/globals";
import type { HostKvApi, JsonValue } from "@grok/agent-sdk";
import { inspect } from "node:util";

import { headersFor, onBehalfOf } from "./connections.js";
import { ConnectionAuthError, FailureReason } from "./errors.js";
import { keycardAuth } from "./keycardAuth.js";
import {
  hostKvSubjectTokenStore,
  memorySubjectTokenStore,
} from "./subjectTokens.js";
import {
  fakeZoneClient,
  session,
  unsignedJwt,
  validJwt,
} from "./testing/testUtils.js";

const ZONE = "https://zone.example.com";
const CALENDAR = "https://calendar.example.com";

interface KvOp {
  readonly op: "get" | "put" | "delete";
  readonly key: string;
}

interface FakeKv extends HostKvApi {
  readonly data: Map<string, JsonValue>;
  readonly ops: KvOp[];
}

function createFakeKv(initial?: Map<string, JsonValue>): FakeKv {
  const data = initial ? new Map(initial) : new Map<string, JsonValue>();
  const ops: KvOp[] = [];
  return {
    data,
    ops,
    async get(key: string): Promise<JsonValue | undefined> {
      ops.push({ op: "get", key });
      const value = data.get(key);
      return value === undefined ? undefined : structuredClone(value);
    },
    async put(key: string, value: JsonValue): Promise<void> {
      ops.push({ op: "put", key });
      data.set(key, structuredClone(value));
    },
    async delete(key: string): Promise<void> {
      ops.push({ op: "delete", key });
      data.delete(key);
    },
  };
}

async function failure(promise: Promise<unknown>): Promise<ConnectionAuthError> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(ConnectionAuthError);
    return error as ConnectionAuthError;
  }
  throw new Error("expected the provider to throw");
}

function deferred<T = void>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

function tokenWithExp(exp: number, sub = "user-1", extra: Record<string, unknown> = {}): string {
  return unsignedJwt({ iss: ZONE, sub, exp, ...extra });
}

function claimsFor(exp: number | undefined, sub = "user-1") {
  return {
    iss: ZONE,
    sub,
    ...(exp !== undefined ? { exp } : {}),
  };
}

afterEach(() => {
  jest.restoreAllMocks();
});

describe("host-kv subject token retention (spec-version 5)", () => {
  it("row 46: fresh instance exchanges KV-retained bearer before exp, isolated by session and subject", async () => {
    const baseMs = 1_700_000_000_000;
    const nowSec = Math.floor(baseMs / 1000);
    jest.spyOn(Date, "now").mockReturnValue(baseMs);

    const kv = createFakeKv();
    const store1 = hostKvSubjectTokenStore();
    store1.attachHostKv(kv);

    const exp = nowSec + 600;
    const token = tokenWithExp(exp, "user-1");
    const verify = keycardAuth({
      zoneUrl: ZONE,
      retainSubjectToken: "host-kv",
      subjectTokens: store1,
      verify: async () => claimsFor(exp, "user-1"),
    });
    const authCtx = await verify(token);
    expect(authCtx).not.toBeNull();

    const client1 = fakeZoneClient({ expiresIn: 300 });
    const provider1 = onBehalfOf({
      resource: CALENDAR,
      zoneUrl: ZONE,
      client: client1,
      subjectTokens: store1,
    });
    await provider1(session(authCtx!, { id: "session-1" }));
    expect(client1.calls.exchanges).toHaveLength(1);
    expect(client1.calls.exchanges[0]?.subjectToken).toBe(token);

    // Fresh instance: new store and provider attached to the same KV, no inbound request.
    jest.spyOn(Date, "now").mockReturnValue(baseMs + 60_000);
    const store2 = hostKvSubjectTokenStore();
    store2.attachHostKv(kv);
    const client2 = fakeZoneClient({ expiresIn: 300 });
    const provider2 = onBehalfOf({
      resource: CALENDAR,
      zoneUrl: ZONE,
      client: client2,
      subjectTokens: store2,
    });

    const resumed = await provider2(session(authCtx!, { id: "session-1" }));
    expect(resumed.headers.authorization).toMatch(/^Bearer exchanged-token-1-for-/);
    expect(client2.calls.exchanges).toHaveLength(1);
    expect(client2.calls.exchanges[0]?.subjectToken).toBe(token);

    // Different session ID in the same issuer fails closed.
    const diffSessionErr = await failure(provider2(session(authCtx!, { id: "session-2" })));
    expect(diffSessionErr.reason).toBe(FailureReason.SUBJECT_TOKEN_UNAVAILABLE);

    // Different subject in the same issuer fails closed.
    const diffUserErr = await failure(
      provider2(session({ ...authCtx!, principalId: "user-2" }, { id: "session-1" })),
    );
    expect(diffUserErr.reason).toBe(FailureReason.SUBJECT_TOKEN_UNAVAILABLE);
    expect(client2.calls.exchanges).toHaveLength(1);
  });

  it("row 46a: provider learns host-kv from store; verifier rejects missing or mismatched store", async () => {
    const baseMs = 1_700_000_000_000;
    const nowSec = Math.floor(baseMs / 1000);
    jest.spyOn(Date, "now").mockReturnValue(baseMs);

    // Missing store for host-kv is rejected at construction.
    expect(() =>
      keycardAuth({
        zoneUrl: ZONE,
        retainSubjectToken: "host-kv",
        verify: async () => claimsFor(nowSec + 600),
      }),
    ).toThrow(/host-kv/);

    // Non-host-kv store with host-kv mode is rejected at construction.
    expect(() =>
      keycardAuth({
        zoneUrl: ZONE,
        retainSubjectToken: "host-kv",
        subjectTokens: memorySubjectTokenStore(),
        verify: async () => claimsFor(nowSec + 600),
      }),
    ).toThrow(/host-kv/);

    // Host KV store with omitted (default memory) or none mode is rejected at construction.
    expect(() =>
      keycardAuth({
        zoneUrl: ZONE,
        subjectTokens: hostKvSubjectTokenStore(),
        verify: async () => claimsFor(nowSec + 600),
      }),
    ).toThrow(/host-kv/);
    expect(() =>
      keycardAuth({
        zoneUrl: ZONE,
        retainSubjectToken: "none",
        subjectTokens: hostKvSubjectTokenStore(),
        verify: async () => claimsFor(nowSec + 600),
      }),
    ).toThrow(/host-kv/);

    // Passing one host-kv store to keycardAuth and onBehalfOf configures lookup,
    // expiry errors (subject_token_unavailable), and session-scoped caching.
    const kv = createFakeKv();
    const store = hostKvSubjectTokenStore();
    store.attachHostKv(kv);
    const exp = nowSec + 300;
    const token = tokenWithExp(exp);
    const verify = keycardAuth({
      zoneUrl: ZONE,
      retainSubjectToken: "host-kv",
      subjectTokens: store,
      verify: async () => claimsFor(exp),
    });
    const authCtx = (await verify(token))!;
    const client = fakeZoneClient({ expiresIn: 600 });
    const provider = onBehalfOf({
      resource: CALENDAR,
      zoneUrl: ZONE,
      client,
      subjectTokens: store,
    });

    // Session-scoped caching: same session reuses cached token, different session exchanges again.
    const s1a = await provider(session(authCtx, { id: "session-1" }));
    const s1b = await provider(session(authCtx, { id: "session-1" }));
    expect(s1b.headers.authorization).toBe(s1a.headers.authorization);
    expect(client.calls.exchanges).toHaveLength(1);

    const s2 = await provider(session(authCtx, { id: "session-2" }));
    expect(s2.headers.authorization).not.toBe(s1a.headers.authorization);
    expect(client.calls.exchanges).toHaveLength(2);

    // At expiry, host-kv reports subject_token_unavailable (not subject_token_expired).
    jest.spyOn(Date, "now").mockReturnValue((exp + 1) * 1000);
    const expiredErr = await failure(provider(session(authCtx, { id: "session-1" })));
    expect(expiredErr.reason).toBe(FailureReason.SUBJECT_TOKEN_UNAVAILABLE);
    expect(client.calls.exchanges).toHaveLength(2);
  });

  it("row 47: expired KV entry is deleted on read without exchange or cached headers; unverified/non-future exp is not written", async () => {
    const baseMs = 1_700_000_000_000;
    const nowSec = Math.floor(baseMs / 1000);
    jest.spyOn(Date, "now").mockReturnValue(baseMs);

    const kv = createFakeKv();
    const store = hostKvSubjectTokenStore();
    store.attachHostKv(kv);

    const exp = nowSec + 300;
    const token = tokenWithExp(exp);
    const verify = keycardAuth({
      zoneUrl: ZONE,
      retainSubjectToken: "host-kv",
      subjectTokens: store,
      verify: async () => claimsFor(exp),
    });
    const authCtx = (await verify(token))!;
    const client = fakeZoneClient({ expiresIn: 3600 });
    const provider = onBehalfOf({
      resource: CALENDAR,
      zoneUrl: ZONE,
      client,
      subjectTokens: store,
    });

    await provider(session(authCtx, { id: "session-1" }));
    expect(client.calls.exchanges).toHaveLength(1);

    const entryKeysBefore = [...kv.data.keys()].filter((k) => k.includes(":entry:"));
    const refKeysBefore = [...kv.data.keys()].filter((k) => k.endsWith(":ref"));
    const listKeysBefore = [...kv.data.keys()].filter((k) => k.endsWith(":list"));
    expect(entryKeysBefore).toHaveLength(1);
    expect(refKeysBefore).toHaveLength(1);
    expect(listKeysBefore).toHaveLength(1);

    // Advance to exp without a turn: expired entry remains until read.
    jest.spyOn(Date, "now").mockReturnValue(exp * 1000);
    expect(kv.data.has(entryKeysBefore[0]!)).toBe(true);

    // Clear local bearer (or expired) and read through the same provider (which had cached headers).
    store.delete(`${ZONE}|user-1`);
    const err = await failure(provider(session(authCtx, { id: "session-1" })));
    expect(err.reason).toBe(FailureReason.SUBJECT_TOKEN_UNAVAILABLE);
    expect(client.calls.exchanges).toHaveLength(1);

    // Only the expired immutable entry was deleted; ref and list remain untouched.
    expect(kv.data.has(entryKeysBefore[0]!)).toBe(false);
    expect(kv.data.has(refKeysBefore[0]!)).toBe(true);
    expect(kv.data.has(listKeysBefore[0]!)).toBe(true);

    // A bearer without a verified future exp is not written to KV.
    const kv2 = createFakeKv();
    const store2 = hostKvSubjectTokenStore();
    store2.attachHostKv(kv2);
    const tokenWithoutVerifiedExp = validJwt(3600, { iss: ZONE });
    const verifyNoExp = keycardAuth({
      zoneUrl: ZONE,
      retainSubjectToken: "host-kv",
      subjectTokens: store2,
      verify: async () => claimsFor(undefined),
    });
    const ctxNoExp = (await verifyNoExp(tokenWithoutVerifiedExp))!;
    const client2 = fakeZoneClient();
    const provider2 = onBehalfOf({
      resource: CALENDAR,
      zoneUrl: ZONE,
      client: client2,
      subjectTokens: store2,
    });
    await provider2(session(ctxNoExp, { id: "session-no-exp" }));
    expect(client2.calls.exchanges).toHaveLength(1);
    expect(kv2.data.size).toBe(0);
    expect(kv2.ops.filter((o) => o.op === "put")).toHaveLength(0);
  });

  it("row 47a: interleaved read of expired KV entry with refresh deletes only old immutable key", async () => {
    const baseMs = 1_700_000_000_000;
    const nowSec = Math.floor(baseMs / 1000);
    jest.spyOn(Date, "now").mockReturnValue(baseMs);

    const backing = new Map<string, JsonValue>();
    const kvPlain = createFakeKv(backing);

    const exp1 = nowSec + 100;
    const token1 = tokenWithExp(exp1, "user-1", { jti: "t1" });
    const store1 = hostKvSubjectTokenStore();
    store1.attachHostKv(kvPlain);
    const verify1 = keycardAuth({
      zoneUrl: ZONE,
      retainSubjectToken: "host-kv",
      subjectTokens: store1,
      verify: async () => claimsFor(exp1),
    });
    const authCtx = (await verify1(token1))!;
    const provider1 = onBehalfOf({
      resource: CALENDAR,
      zoneUrl: ZONE,
      client: fakeZoneClient(),
      subjectTokens: store1,
    });
    await provider1(session(authCtx, { id: "session-1" }));

    const oldEntryKey = [...kvPlain.data.keys()].find((k) => k.includes(":entry:"))!;
    expect(oldEntryKey).toBeDefined();

    // Advance past exp1.
    const laterMs = (exp1 + 10) * 1000;
    jest.spyOn(Date, "now").mockReturnValue(laterMs);

    // Intercept the stale read right before its delete of the old immutable key.
    const reachedDelete = deferred();
    const allowDelete = deferred();
    const pausedReadKv: HostKvApi = {
      async get(key) {
        return kvPlain.get(key);
      },
      async put(key, value) {
        return kvPlain.put(key, value);
      },
      async delete(key) {
        if (key === oldEntryKey) {
          reachedDelete.resolve();
          await allowDelete.promise;
        }
        return kvPlain.delete(key);
      },
    };

    const staleStore = hostKvSubjectTokenStore();
    staleStore.attachHostKv(pausedReadKv);
    const staleProvider = onBehalfOf({
      resource: CALENDAR,
      zoneUrl: ZONE,
      client: fakeZoneClient(),
      subjectTokens: staleStore,
    });

    const staleReadPromise = failure(staleProvider(session(authCtx, { id: "session-1" })));
    await reachedDelete.promise;

    // While stale read is paused before delete, a built-in route refresh publishes token2.
    const exp2 = exp1 + 600;
    const token2 = tokenWithExp(exp2, "user-1", { jti: "t2" });
    const refreshStore = hostKvSubjectTokenStore();
    refreshStore.attachHostKv(kvPlain);
    const verify2 = keycardAuth({
      zoneUrl: ZONE,
      retainSubjectToken: "host-kv",
      subjectTokens: refreshStore,
      verify: async () => claimsFor(exp2),
    });
    await verify2(token2);
    const refreshProvider = onBehalfOf({
      resource: CALENDAR,
      zoneUrl: ZONE,
      client: fakeZoneClient(),
      subjectTokens: refreshStore,
    });
    await refreshProvider(session(authCtx, { id: "session-1" }));

    // Resume the stale read's delete.
    allowDelete.resolve();
    const staleErr = await staleReadPromise;
    expect(staleErr.reason).toBe(FailureReason.SUBJECT_TOKEN_UNAVAILABLE);

    // Fresh lookup still exchanges the replacement bearer token2.
    const freshStore = hostKvSubjectTokenStore();
    freshStore.attachHostKv(kvPlain);
    const freshClient = fakeZoneClient();
    const freshProvider = onBehalfOf({
      resource: CALENDAR,
      zoneUrl: ZONE,
      client: freshClient,
      subjectTokens: freshStore,
    });
    await freshProvider(session(authCtx, { id: "session-1" }));
    expect(freshClient.calls.exchanges).toHaveLength(1);
    expect(freshClient.calls.exchanges[0]?.subjectToken).toBe(token2);
  });

  it("row 47b: write prunes expired entries for same session and principal, leaving unexpired entries and other sessions untouched", async () => {
    const baseMs = 1_700_000_000_000;
    const nowSec = Math.floor(baseMs / 1000);
    jest.spyOn(Date, "now").mockReturnValue(baseMs);

    const kv = createFakeKv();
    const store = hostKvSubjectTokenStore();
    store.attachHostKv(kv);

    let currentExp = nowSec + 100;
    const verify = keycardAuth({
      zoneUrl: ZONE,
      retainSubjectToken: "host-kv",
      subjectTokens: store,
      verify: async () => claimsFor(currentExp),
    });
    const provider = onBehalfOf({
      resource: CALENDAR,
      zoneUrl: ZONE,
      client: fakeZoneClient(),
      subjectTokens: store,
    });

    // Publish entry 1 (exp +100) for session-1 and an entry (exp +100) for session-2.
    const token1 = tokenWithExp(currentExp, "user-1", { jti: "1" });
    const authCtx = (await verify(token1))!;
    await provider(session(authCtx, { id: "session-1" }));
    const s1Entry1 = [...kv.data.keys()].find((k) => k.includes(":entry:"))!;

    await provider(session(authCtx, { id: "session-2" }));
    const s2Entry = [...kv.data.keys()].find((k) => k.includes(":entry:") && k !== s1Entry1)!;

    // Publish entry 2 (exp +400) for session-1 while entry 1 is still live.
    currentExp = nowSec + 400;
    const token2 = tokenWithExp(currentExp, "user-1", { jti: "2" });
    await verify(token2);
    await provider(session(authCtx, { id: "session-1" }));
    const s1Entry2 = [...kv.data.keys()].find(
      (k) => k.includes(":entry:") && k !== s1Entry1 && k !== s2Entry,
    )!;

    // Advance to nowSec + 150: s1Entry1 and s2Entry are expired; s1Entry2 is still live.
    jest.spyOn(Date, "now").mockReturnValue((nowSec + 150) * 1000);

    // Publish entry 3 (exp +800) for session-1.
    currentExp = nowSec + 800;
    const token3 = tokenWithExp(currentExp, "user-1", { jti: "3" });
    await verify(token3);
    await provider(session(authCtx, { id: "session-1" }));

    // Expired s1Entry1 was deleted; unexpired s1Entry2 and other session's s2Entry remain untouched.
    expect(kv.data.has(s1Entry1)).toBe(false);
    expect(kv.data.has(s1Entry2)).toBe(true);
    expect(kv.data.has(s2Entry)).toBe(true);

    // Fresh instance on session-1 exchanges token3.
    const freshStore = hostKvSubjectTokenStore();
    freshStore.attachHostKv(kv);
    const freshClient = fakeZoneClient();
    const freshProvider = onBehalfOf({
      resource: CALENDAR,
      zoneUrl: ZONE,
      client: freshClient,
      subjectTokens: freshStore,
    });
    await freshProvider(session(authCtx, { id: "session-1" }));
    expect(freshClient.calls.exchanges[0]?.subjectToken).toBe(token3);
  });

  it("row 47c: list put registers new ID before bearer write; reference put occurs only after bearer write succeeds", async () => {
    const baseMs = 1_700_000_000_000;
    const nowSec = Math.floor(baseMs / 1000);
    jest.spyOn(Date, "now").mockReturnValue(baseMs);

    const kv = createFakeKv();
    const store = hostKvSubjectTokenStore();
    store.attachHostKv(kv);

    let currentExp = nowSec + 100;
    const verify = keycardAuth({
      zoneUrl: ZONE,
      retainSubjectToken: "host-kv",
      subjectTokens: store,
      verify: async () => claimsFor(currentExp),
    });
    const provider = onBehalfOf({
      resource: CALENDAR,
      zoneUrl: ZONE,
      client: fakeZoneClient(),
      subjectTokens: store,
    });

    const token1 = tokenWithExp(currentExp, "user-1", { jti: "1" });
    const authCtx = (await verify(token1))!;
    await provider(session(authCtx, { id: "session-1" }));

    // Record puts during the refresh with a later-expiring bearer.
    kv.ops.length = 0;
    currentExp = nowSec + 500;
    const token2 = tokenWithExp(currentExp, "user-1", { jti: "2" });
    await verify(token2);
    await provider(session(authCtx, { id: "session-1" }));

    const puts = kv.ops.filter((o) => o.op === "put").map((o) => o.key);
    expect(puts).toHaveLength(3);
    expect(puts[0]).toMatch(/:list$/);
    expect(puts[1]).toMatch(/:entry:/);
    expect(puts[2]).toMatch(/:ref$/);

    // Verify neither list nor ref holds any bearer.
    for (const [key, value] of kv.data) {
      if (key.endsWith(":list") || key.endsWith(":ref")) {
        expect(JSON.stringify(value)).not.toContain(token1);
        expect(JSON.stringify(value)).not.toContain(token2);
      }
    }
  });

  it("row 47d: overlapping refresh A fails bearer write after lost list race; fresh instance exchanges B and later write prunes A", async () => {
    const baseMs = 1_700_000_000_000;
    const nowSec = Math.floor(baseMs / 1000);
    jest.spyOn(Date, "now").mockReturnValue(baseMs);

    const kvPlain = createFakeKv();
    const expA = nowSec + 200;
    const expB = nowSec + 400;
    const tokenA = tokenWithExp(expA, "user-1", { jti: "A" });
    const tokenB = tokenWithExp(expB, "user-1", { jti: "B" });

    // Intercept refresh A after it reads KV and before its list put; fail its bearer write.
    const aReadyToPutList = deferred();
    const allowAListPut = deferred();
    let aRefPuts = 0;
    let aEntryId: string | undefined;

    const kvForA: HostKvApi = {
      async get(key) {
        return kvPlain.get(key);
      },
      async put(key, value) {
        if (key.endsWith(":list")) {
          aReadyToPutList.resolve();
          await allowAListPut.promise;
          const entries = (value as { entries: Array<{ id: string }> }).entries;
          aEntryId = entries[entries.length - 1]?.id;
          return kvPlain.put(key, value);
        }
        if (key.includes(":entry:")) {
          throw new Error("simulated bearer write failure");
        }
        if (key.endsWith(":ref")) {
          aRefPuts += 1;
          return kvPlain.put(key, value);
        }
        return kvPlain.put(key, value);
      },
      async delete(key) {
        return kvPlain.delete(key);
      },
    };

    const storeA = hostKvSubjectTokenStore();
    storeA.attachHostKv(kvForA);
    const verifyA = keycardAuth({
      zoneUrl: ZONE,
      retainSubjectToken: "host-kv",
      subjectTokens: storeA,
      verify: async () => claimsFor(expA),
    });
    const authCtx = (await verifyA(tokenA))!;
    const providerA = onBehalfOf({
      resource: CALENDAR,
      zoneUrl: ZONE,
      client: fakeZoneClient(),
      subjectTokens: storeA,
    });

    const aPromise = providerA(session(authCtx, { id: "session-1" }));
    await aReadyToPutList.promise;

    // While A is paused, refresh B publishes a live bearer to the same session and principal.
    const storeB = hostKvSubjectTokenStore();
    storeB.attachHostKv(kvPlain);
    const verifyB = keycardAuth({
      zoneUrl: ZONE,
      retainSubjectToken: "host-kv",
      subjectTokens: storeB,
      verify: async () => claimsFor(expB),
    });
    await verifyB(tokenB);
    const providerB = onBehalfOf({
      resource: CALENDAR,
      zoneUrl: ZONE,
      client: fakeZoneClient(),
      subjectTokens: storeB,
    });
    await providerB(session(authCtx, { id: "session-1" }));

    // Resume A: A overwrites the list (losing B's ID from the list) and fails its bearer write.
    allowAListPut.resolve();
    await aPromise;
    expect(aRefPuts).toBe(0);
    expect(aEntryId).toBeDefined();

    // Fresh instance exchanges B's bearer even though B's ID was lost from the list.
    const freshStore = hostKvSubjectTokenStore();
    freshStore.attachHostKv(kvPlain);
    const freshClient = fakeZoneClient();
    const freshProvider = onBehalfOf({
      resource: CALENDAR,
      zoneUrl: ZONE,
      client: freshClient,
      subjectTokens: freshStore,
    });
    await freshProvider(session(authCtx, { id: "session-1" }));
    expect(freshClient.calls.exchanges).toHaveLength(1);
    expect(freshClient.calls.exchanges[0]?.subjectToken).toBe(tokenB);

    // Advance past A's verified exp and publish C: A's expired ID is pruned from the list.
    jest.spyOn(Date, "now").mockReturnValue((expA + 10) * 1000);
    const expC = nowSec + 800;
    const tokenC = tokenWithExp(expC, "user-1", { jti: "C" });
    const storeC = hostKvSubjectTokenStore();
    storeC.attachHostKv(kvPlain);
    const verifyC = keycardAuth({
      zoneUrl: ZONE,
      retainSubjectToken: "host-kv",
      subjectTokens: storeC,
      verify: async () => claimsFor(expC),
    });
    await verifyC(tokenC);
    const providerC = onBehalfOf({
      resource: CALENDAR,
      zoneUrl: ZONE,
      client: fakeZoneClient(),
      subjectTokens: storeC,
    });
    await providerC(session(authCtx, { id: "session-1" }));

    const listKey = [...kvPlain.data.keys()].find((k) => k.endsWith(":list"))!;
    const listRecord = kvPlain.data.get(listKey) as { entries: Array<{ id: string; exp: number }> };
    expect(listRecord.entries.map((e) => e.id)).not.toContain(aEntryId);
  });

  it("row 48: only KV stores the bearer durably; session.auth, printed store, and headers never expose it", async () => {
    const baseMs = 1_700_000_000_000;
    const nowSec = Math.floor(baseMs / 1000);
    jest.spyOn(Date, "now").mockReturnValue(baseMs);

    const kv = createFakeKv();
    const store = hostKvSubjectTokenStore();
    store.attachHostKv(kv);

    const exp = nowSec + 600;
    const token = tokenWithExp(exp, "user-1", { jti: "secret-bearer" });
    const verify = keycardAuth({
      zoneUrl: ZONE,
      retainSubjectToken: "host-kv",
      subjectTokens: store,
      verify: async () => claimsFor(exp),
    });
    const authCtx = (await verify(token))!;
    const sessionRecord = session(authCtx, { id: "session-1" });

    const provider = onBehalfOf({
      resource: CALENDAR,
      zoneUrl: ZONE,
      client: fakeZoneClient(),
      subjectTokens: store,
    });
    const result = await provider(sessionRecord);

    // Session auth and session record never contain the bearer.
    expect(JSON.stringify(authCtx)).not.toContain(token);
    expect(JSON.stringify(sessionRecord)).not.toContain(token);
    // Returned connection headers carry the exchanged token, never the subject bearer.
    expect(JSON.stringify(result)).not.toContain(token);
    // Printed store never reveals the bearer.
    expect(inspect(store)).not.toContain(token);

    // Only the immutable KV entry contains the bearer.
    const keysHoldingBearer = [...kv.data.entries()]
      .filter(([, value]) => JSON.stringify(value).includes(token))
      .map(([key]) => key);
    expect(keysHoldingBearer).toHaveLength(1);
    expect(keysHoldingBearer[0]).toMatch(/:entry:/);
  });

  it("row 48a: latest verified bearer occupies local slot and publishes to KV; without KV first turn succeeds locally and fresh instance fails", async () => {
    const baseMs = 1_700_000_000_000;
    const nowSec = Math.floor(baseMs / 1000);
    jest.spyOn(Date, "now").mockReturnValue(baseMs);

    const kv = createFakeKv();
    const store = hostKvSubjectTokenStore();
    store.attachHostKv(kv);

    const exp1 = nowSec + 300;
    const exp2 = nowSec + 600;
    const token1 = tokenWithExp(exp1, "user-1", { jti: "first" });
    const token2 = tokenWithExp(exp2, "user-1", { jti: "second" });
    const verify = keycardAuth({
      zoneUrl: ZONE,
      retainSubjectToken: "host-kv",
      subjectTokens: store,
      verify: async (tok) => claimsFor(tok === token1 ? exp1 : exp2),
    });

    await verify(token1);
    const authCtx = (await verify(token2))!;

    const client1 = fakeZoneClient();
    const provider1 = onBehalfOf({
      resource: CALENDAR,
      zoneUrl: ZONE,
      client: client1,
      subjectTokens: store,
    });
    await provider1(session(authCtx, { id: "session-1" }));
    expect(client1.calls.exchanges).toHaveLength(1);
    expect(client1.calls.exchanges[0]?.subjectToken).toBe(token2);

    // Fresh instance exchanges token2 from KV.
    const freshStore = hostKvSubjectTokenStore();
    freshStore.attachHostKv(kv);
    const freshClient = fakeZoneClient();
    const freshProvider = onBehalfOf({
      resource: CALENDAR,
      zoneUrl: ZONE,
      client: freshClient,
      subjectTokens: freshStore,
    });
    await freshProvider(session(authCtx, { id: "session-1" }));
    expect(freshClient.calls.exchanges).toHaveLength(1);
    expect(freshClient.calls.exchanges[0]?.subjectToken).toBe(token2);

    // Repeat without KV attached: first turn still succeeds locally, fresh instance fails.
    const noKvStore = hostKvSubjectTokenStore();
    const verifyNoKv = keycardAuth({
      zoneUrl: ZONE,
      retainSubjectToken: "host-kv",
      subjectTokens: noKvStore,
      verify: async () => claimsFor(exp2),
    });
    const ctxNoKv = (await verifyNoKv(token2))!;
    const localClient = fakeZoneClient();
    const localProvider = onBehalfOf({
      resource: CALENDAR,
      zoneUrl: ZONE,
      client: localClient,
      subjectTokens: noKvStore,
    });
    await localProvider(session(ctxNoKv, { id: "session-no-kv" }));
    expect(localClient.calls.exchanges).toHaveLength(1);

    const freshNoKvStore = hostKvSubjectTokenStore();
    const freshNoKvClient = fakeZoneClient();
    const freshNoKvProvider = onBehalfOf({
      resource: CALENDAR,
      zoneUrl: ZONE,
      client: freshNoKvClient,
      subjectTokens: freshNoKvStore,
    });
    const err = await failure(freshNoKvProvider(session(ctxNoKv, { id: "session-no-kv" })));
    expect(err.reason).toBe(FailureReason.SUBJECT_TOKEN_UNAVAILABLE);
    expect(freshNoKvClient.calls.exchanges).toHaveLength(0);
  });

  it("row 48b: follow-up after expiry with unchanged session auth refreshes KV reference and fresh instance exchanges new bearer", async () => {
    const baseMs = 1_700_000_000_000;
    const nowSec = Math.floor(baseMs / 1000);
    jest.spyOn(Date, "now").mockReturnValue(baseMs);

    const kv = createFakeKv();
    const store = hostKvSubjectTokenStore();
    store.attachHostKv(kv);

    let currentExp = nowSec + 100;
    const verify = keycardAuth({
      zoneUrl: ZONE,
      retainSubjectToken: "host-kv",
      subjectTokens: store,
      verify: async () => claimsFor(currentExp),
    });
    const client = fakeZoneClient();
    const provider = onBehalfOf({
      resource: CALENDAR,
      zoneUrl: ZONE,
      client,
      subjectTokens: store,
    });

    const token1 = tokenWithExp(currentExp, "user-1", { jti: "turn-1" });
    const sessionAuth = (await verify(token1))!;
    await provider(session(sessionAuth, { id: "session-1" }));
    const refKey = [...kv.data.keys()].find((k) => k.endsWith(":ref"))!;
    const firstRefId = (kv.data.get(refKey) as { id: string }).id;

    // Advance past token1's exp, verify fresh token2, acquire on follow-up with unchanged sessionAuth.
    jest.spyOn(Date, "now").mockReturnValue((currentExp + 10) * 1000);
    currentExp = nowSec + 700;
    const token2 = tokenWithExp(currentExp, "user-1", { jti: "turn-2" });
    await verify(token2);

    await provider(session(sessionAuth, { id: "session-1" }));
    expect(client.calls.exchanges).toHaveLength(2);
    expect(client.calls.exchanges[1]?.subjectToken).toBe(token2);

    const secondRefId = (kv.data.get(refKey) as { id: string }).id;
    expect(secondRefId).not.toBe(firstRefId);

    // Fresh instance exchanges token2.
    const freshStore = hostKvSubjectTokenStore();
    freshStore.attachHostKv(kv);
    const freshClient = fakeZoneClient();
    const freshProvider = onBehalfOf({
      resource: CALENDAR,
      zoneUrl: ZONE,
      client: freshClient,
      subjectTokens: freshStore,
    });
    await freshProvider(session(sessionAuth, { id: "session-1" }));
    expect(freshClient.calls.exchanges).toHaveLength(1);
    expect(freshClient.calls.exchanges[0]?.subjectToken).toBe(token2);
  });

  it("row 48c: shorter-lived local bearer does not overwrite a longer-lived KV reference on reminder", async () => {
    const baseMs = 1_700_000_000_000;
    const nowSec = Math.floor(baseMs / 1000);
    jest.spyOn(Date, "now").mockReturnValue(baseMs);

    const kv = createFakeKv();
    const store = hostKvSubjectTokenStore();
    store.attachHostKv(kv);

    const longExp = nowSec + 600;
    const shortExp = nowSec + 100;
    const longToken = tokenWithExp(longExp, "user-1", { jti: "long" });
    const shortToken = tokenWithExp(shortExp, "user-1", { jti: "short" });

    const verify = keycardAuth({
      zoneUrl: ZONE,
      retainSubjectToken: "host-kv",
      subjectTokens: store,
      verify: async (tok) => claimsFor(tok === longToken ? longExp : shortExp),
    });
    const provider = onBehalfOf({
      resource: CALENDAR,
      zoneUrl: ZONE,
      client: fakeZoneClient(),
      subjectTokens: store,
    });

    // Session 1 publishes the long-lived bearer.
    const authCtx = (await verify(longToken))!;
    await provider(session(authCtx, { id: "session-1" }));
    const refKey = [...kv.data.keys()].find((k) => k.endsWith(":ref"))!;
    const originalRef = kv.data.get(refKey);

    // Another session for the same principal verifies a shorter-lived bearer on the same instance.
    await verify(shortToken);

    // Reminder runs for session-1 while shortToken is still live: leaves KV reference unchanged.
    await provider(session(authCtx, { id: "session-1" }));
    expect(kv.data.get(refKey)).toEqual(originalRef);

    // Advance past shortExp but before longExp; fresh instance exchanges longToken.
    jest.spyOn(Date, "now").mockReturnValue((shortExp + 50) * 1000);
    const freshStore = hostKvSubjectTokenStore();
    freshStore.attachHostKv(kv);
    const freshClient = fakeZoneClient();
    const freshProvider = onBehalfOf({
      resource: CALENDAR,
      zoneUrl: ZONE,
      client: freshClient,
      subjectTokens: freshStore,
    });
    await freshProvider(session(authCtx, { id: "session-1" }));
    expect(freshClient.calls.exchanges).toHaveLength(1);
    expect(freshClient.calls.exchanges[0]?.subjectToken).toBe(longToken);
  });

  it("row 49: default retention uses memory only with no KV access and fails closed on a fresh instance", async () => {
    const store1 = memorySubjectTokenStore();
    const token = validJwt(3600, { iss: ZONE });
    const verify = keycardAuth({
      zoneUrl: ZONE,
      subjectTokens: store1,
      verify: async () => claimsFor(Math.floor(Date.now() / 1000) + 3600),
    });
    const authCtx = (await verify(token))!;

    const client1 = fakeZoneClient();
    const provider1 = onBehalfOf({
      resource: CALENDAR,
      zoneUrl: ZONE,
      client: client1,
      subjectTokens: store1,
    });
    await provider1(session(authCtx, { id: "session-1" }));
    expect(client1.calls.exchanges).toHaveLength(1);
    expect(client1.calls.exchanges[0]?.subjectToken).toBe(token);

    // Fresh instance with a new default memory store fails with subject_token_unavailable.
    const store2 = memorySubjectTokenStore();
    const client2 = fakeZoneClient();
    const provider2 = onBehalfOf({
      resource: CALENDAR,
      zoneUrl: ZONE,
      client: client2,
      subjectTokens: store2,
    });
    const err = await failure(provider2(session(authCtx, { id: "session-1" })));
    expect(err.reason).toBe(FailureReason.SUBJECT_TOKEN_UNAVAILABLE);
    expect(client2.calls.exchanges).toHaveLength(0);
  });

  it("row 50: failing list put skips bearer and ref writes while using local bearer; local miss with no KV or read failure fails closed", async () => {
    const baseMs = 1_700_000_000_000;
    const nowSec = Math.floor(baseMs / 1000);
    jest.spyOn(Date, "now").mockReturnValue(baseMs);

    const attemptedPuts: string[] = [];
    const failingListKv: HostKvApi = {
      async get() {
        return undefined;
      },
      async put(key) {
        attemptedPuts.push(key);
        if (key.endsWith(":list")) {
          throw new Error("list put failed");
        }
      },
      async delete() {},
    };

    const store = hostKvSubjectTokenStore();
    store.attachHostKv(failingListKv);
    const exp = nowSec + 600;
    const token = tokenWithExp(exp);
    const verify = keycardAuth({
      zoneUrl: ZONE,
      retainSubjectToken: "host-kv",
      subjectTokens: store,
      verify: async () => claimsFor(exp),
    });
    const authCtx = (await verify(token))!;

    const client = fakeZoneClient({ expiresIn: 3600 });
    const provider = onBehalfOf({
      resource: CALENDAR,
      zoneUrl: ZONE,
      client,
      subjectTokens: store,
    });

    // First acquisition exchanges local bearer without writing bearer or ref to KV.
    await provider(session(authCtx, { id: "session-1" }));
    expect(client.calls.exchanges).toHaveLength(1);
    expect(attemptedPuts).toHaveLength(1);
    expect(attemptedPuts[0]).toMatch(/:list$/);

    // Local miss with failing KV read fails closed without exchange or cached headers.
    const failingReadKv: HostKvApi = {
      async get() {
        throw new Error("kv read failed");
      },
      async put() {},
      async delete() {},
    };
    store.delete(`${ZONE}|user-1`);
    store.attachHostKv(failingReadKv);
    const readFailErr = await failure(provider(session(authCtx, { id: "session-1" })));
    expect(readFailErr.reason).toBe(FailureReason.SUBJECT_TOKEN_UNAVAILABLE);
    expect(client.calls.exchanges).toHaveLength(1);

    // Local miss with KV not attached also fails closed without exchange or cached headers.
    const unattachedStore = hostKvSubjectTokenStore();
    const unattachedClient = fakeZoneClient();
    const unattachedProvider = onBehalfOf({
      resource: CALENDAR,
      zoneUrl: ZONE,
      client: unattachedClient,
      subjectTokens: unattachedStore,
    });
    const unattachedErr = await failure(
      unattachedProvider(session(authCtx, { id: "session-1" })),
    );
    expect(unattachedErr.reason).toBe(FailureReason.SUBJECT_TOKEN_UNAVAILABLE);
    expect(unattachedClient.calls.exchanges).toHaveLength(0);
  });

  it("row 50a: sessionless headersFor in host-kv mode uses local bearer only, skipping KV and cache", async () => {
    const baseMs = 1_700_000_000_000;
    const nowSec = Math.floor(baseMs / 1000);
    jest.spyOn(Date, "now").mockReturnValue(baseMs);

    const kv = createFakeKv();
    const store = hostKvSubjectTokenStore();
    store.attachHostKv(kv);

    const exp = nowSec + 600;
    const token = tokenWithExp(exp);
    const verify = keycardAuth({
      zoneUrl: ZONE,
      retainSubjectToken: "host-kv",
      subjectTokens: store,
      verify: async () => claimsFor(exp),
    });
    const authCtx = (await verify(token))!;

    const client = fakeZoneClient({ expiresIn: 3600 });
    const provider = onBehalfOf({
      resource: CALENDAR,
      zoneUrl: ZONE,
      client,
      subjectTokens: store,
    });

    // Seed a live KV copy and session-scoped cache entry via a sessioned call.
    await provider(session(authCtx, { id: "session-1" }));
    expect(client.calls.exchanges).toHaveLength(1);
    kv.ops.length = 0;

    // Sessionless headersFor with a live local bearer exchanges directly, skipping KV and cache.
    const r1 = await headersFor(provider, { auth: authCtx });
    const r2 = await headersFor(provider, { auth: authCtx });
    expect(r1.headers.authorization).not.toBe(r2.headers.authorization);
    expect(client.calls.exchanges).toHaveLength(3);
    expect(kv.ops).toHaveLength(0);

    // Remove the local bearer while leaving the live KV copy for session-1 intact.
    store.delete(`${ZONE}|user-1`);
    const err = await failure(headersFor(provider, { auth: authCtx }));
    expect(err.reason).toBe(FailureReason.SUBJECT_TOKEN_UNAVAILABLE);
    expect(client.calls.exchanges).toHaveLength(3);
    expect(kv.ops).toHaveLength(0);
  });

  it("serializes concurrent first-turn publications across parallel connections on the same store", async () => {
    const baseMs = 1_700_000_000_000;
    const nowSec = Math.floor(baseMs / 1000);
    jest.spyOn(Date, "now").mockReturnValue(baseMs);

    const kv = createFakeKv();
    const store = hostKvSubjectTokenStore();
    store.attachHostKv(kv);

    const exp = nowSec + 600;
    const token = tokenWithExp(exp);
    const verify = keycardAuth({
      zoneUrl: ZONE,
      retainSubjectToken: "host-kv",
      subjectTokens: store,
      verify: async () => claimsFor(exp),
    });
    const authCtx = (await verify(token))!;

    const clientA = fakeZoneClient();
    const clientB = fakeZoneClient();
    const connA = onBehalfOf({
      resource: CALENDAR,
      zoneUrl: ZONE,
      client: clientA,
      subjectTokens: store,
    });
    const connB = onBehalfOf({
      resource: "https://mail.example.com",
      zoneUrl: ZONE,
      client: clientB,
      subjectTokens: store,
    });

    await Promise.all([
      connA(session(authCtx, { id: "session-1" })),
      connB(session(authCtx, { id: "session-1" })),
    ]);

    const entryKeys = [...kv.data.keys()].filter((k) => k.includes(":entry:"));
    expect(entryKeys).toHaveLength(1);
    const listKey = [...kv.data.keys()].find((k) => k.endsWith(":list"))!;
    const list = kv.data.get(listKey) as { entries: Array<{ id: string; exp: number }> };
    expect(list.entries).toHaveLength(1);
    expect(entryKeys[0]).toContain(list.entries[0]!.id);
  });

  it("prunes expired session entries from the exchange cache when later sessions run", async () => {
    const baseMs = 1_700_000_000_000;
    const nowSec = Math.floor(baseMs / 1000);
    const nowSpy = jest.spyOn(Date, "now").mockReturnValue(baseMs);

    const kv = createFakeKv();
    const store = hostKvSubjectTokenStore();
    store.attachHostKv(kv);

    const client = fakeZoneClient();
    const provider = onBehalfOf({
      resource: CALENDAR,
      zoneUrl: ZONE,
      client,
      subjectTokens: store,
    });

    const exp1 = nowSec + 120;
    const token1 = tokenWithExp(exp1, "user-1");
    const verify1 = keycardAuth({
      zoneUrl: ZONE,
      retainSubjectToken: "host-kv",
      subjectTokens: store,
      verify: async () => claimsFor(exp1, "user-1"),
    });
    const auth1 = (await verify1(token1))!;
    await provider(session(auth1, { id: "session-finished" }));

    // Advance past session-finished's expiry and run a new session.
    nowSpy.mockReturnValue((exp1 + 10) * 1000);
    const exp2 = exp1 + 600;
    const token2 = tokenWithExp(exp2, "user-2");
    const verify2 = keycardAuth({
      zoneUrl: ZONE,
      retainSubjectToken: "host-kv",
      subjectTokens: store,
      verify: async () => claimsFor(exp2, "user-2"),
    });
    const auth2 = (await verify2(token2))!;
    await provider(session(auth2, { id: "session-active" }));

    // Even if clocks or callers revisit session-finished with the old token,
    // its expired entry was pruned and cannot be served from cache.
    nowSpy.mockReturnValue(baseMs);
    store.set(`${ZONE}|user-1`, token1, exp1);
    await provider(session(auth1, { id: "session-finished" }));
    expect(client.calls.exchanges).toHaveLength(3);
  });
});
