import { createHash, randomUUID } from "node:crypto";
import type { AuthContext, HostKvApi, JsonValue } from "@grok/agent-sdk";

import { decodeClaims } from "./expiry.js";

/**
 * A reserved attribute name that never carries a token.
 *
 * `AuthContext.attributes` is persisted in `SessionRecord.auth`
 * (`sessions/<id>/session.json`), so a token there would be a bearer at rest.
 * `keycardAuth` strips this name from the attributes it returns, and nothing
 * under it is ever read as a token.
 */
export const SUBJECT_TOKEN_ATTRIBUTE = "keycard_subject_token";

/**
 * Where the verified inbound bearer lives between `bearerAuth` admitting the
 * request and the exchange in `onBehalfOf`.
 *
 * Two implementations ship: {@link memorySubjectTokenStore} (process-local,
 * nothing at rest) and {@link hostKvSubjectTokenStore} (opt-in process-local
 * plus host KV retention for hosted Cursor agents). The token never reaches
 * the model (it is never a tool argument, a connection schema field, or a
 * message) and never the session record, which Cursor persists.
 */
export interface SubjectTokenStore {
  get(key: string): string | undefined;
  set(key: string, token: string): void;
  delete(key: string): void;
}

/** A live bearer entry read from host KV for one session and principal. */
export interface HostKvSubjectTokenEntry {
  readonly id: string;
  readonly token: string;
  /** Verified expiry in epoch seconds. */
  readonly exp: number;
}

/** A process-local retained bearer and its verified `exp` when known. */
export interface LocalSubjectTokenEntry {
  readonly token: string;
  /** Verified expiry in epoch seconds, when available from verified claims. */
  readonly exp?: number;
}

/**
 * Host KV subject-token store for opt-in `"host-kv"` retention.
 *
 * Shares private process-local entries between `keycardAuth` and `onBehalfOf`
 * within one runtime, and uses the deployment's `HostKvApi` across runtimes.
 */
export interface HostKvSubjectTokenStore extends SubjectTokenStore {
  readonly mode: "host-kv";
  /** Supplies the deployment-local `HostKvApi` handle for reads and writes in this runtime. */
  attachHostKv(kv: HostKvApi): void;
  /**
   * Host-only lookup through the attached handle. Returns a live entry's ID,
   * bearer, and verified `exp`, or undefined if missing, expired, or inaccessible.
   */
  readSubjectToken(
    sessionId: string,
    issuer: string,
    subject: string,
  ): Promise<HostKvSubjectTokenEntry | undefined>;
  /** Retains a verified bearer in process-local storage, optionally with its verified `exp`. */
  set(key: string, token: string, verifiedExp?: number): void;
  /** Reads the live process-local entry for a principal, pruning it if expired. */
  getLocalEntry?(issuer: string, subject: string): LocalSubjectTokenEntry | undefined;
  /**
   * Best-effort publication of a verified bearer to host KV for a session and
   * principal. Never throws; skips publication if KV is not attached, `exp` is
   * not a finite future timestamp, or a live KV copy expires at or after `exp`.
   */
  publishSubjectToken?(
    sessionId: string,
    issuer: string,
    subject: string,
    token: string,
    exp: number,
  ): Promise<void>;
}

/** Type guard identifying a host KV subject-token store. */
export function isHostKvSubjectTokenStore(
  store: SubjectTokenStore | null | undefined,
): store is HostKvSubjectTokenStore {
  return (
    typeof store === "object" &&
    store !== null &&
    "mode" in store &&
    (store as { mode?: unknown }).mode === "host-kv" &&
    typeof (store as { attachHostKv?: unknown }).attachHostKv === "function" &&
    typeof (store as { readSubjectToken?: unknown }).readSubjectToken === "function"
  );
}

/**
 * A process-local store that drops entries once their JWT `exp` has passed.
 *
 * Nothing here survives a restart, so a turn that runs in a fresh process
 * finds no subject token and fails closed with `subject_token_unavailable`
 * rather than reaching for the agent's authority.
 */
export function memorySubjectTokenStore(): SubjectTokenStore {
  const tokens = new Map<string, string>();
  return {
    get(key) {
      return tokens.get(key);
    },
    set(key, token) {
      for (const [existing, value] of tokens) {
        if (tokenExpired(value)) tokens.delete(existing);
      }
      tokens.set(key, token);
    },
    delete(key) {
      tokens.delete(key);
    },
  };
}

interface KvRefRecord {
  readonly id: string;
  readonly exp: number;
}

interface KvEntryRecord {
  readonly id: string;
  readonly token: string;
  readonly exp: number;
}

/**
 * An opt-in subject-token store backed by process-local memory and Cursor's
 * `HostKvApi`.
 *
 * Attach the deployment's `HostKvApi` handle at startup via `attachHostKv(kv)`.
 * Within one runtime, verified bearers are retained per principal in memory;
 * on built-in routes with a session ID, live bearers with a verified future
 * `exp` are published to immutable KV keys scoped by session ID, verified
 * issuer, and subject.
 */
export function hostKvSubjectTokenStore(): HostKvSubjectTokenStore {
  const local = new Map<string, LocalSubjectTokenEntry>();
  const pendingPublishes = new Map<string, Promise<void>>();
  let kv: HostKvApi | undefined;

  return {
    mode: "host-kv",
    attachHostKv(handle: HostKvApi): void {
      kv = handle;
    },
    get(key: string): string | undefined {
      const entry = local.get(key);
      if (!entry) return undefined;
      if (isLocalEntryExpired(entry, nowSeconds())) {
        local.delete(key);
        return undefined;
      }
      return entry.token;
    },
    set(key: string, token: string, verifiedExp?: number): void {
      const nowSec = nowSeconds();
      for (const [existingKey, existingEntry] of local) {
        if (isLocalEntryExpired(existingEntry, nowSec)) {
          local.delete(existingKey);
        }
      }
      const exp =
        typeof verifiedExp === "number" && Number.isFinite(verifiedExp) ? verifiedExp : undefined;
      local.set(key, exp !== undefined ? { token, exp } : { token });
    },
    delete(key: string): void {
      local.delete(key);
    },
    getLocalEntry(issuer: string, subject: string): LocalSubjectTokenEntry | undefined {
      const key = `${issuer}|${subject}`;
      const entry = local.get(key);
      if (!entry) return undefined;
      if (isLocalEntryExpired(entry, nowSeconds())) {
        local.delete(key);
        return undefined;
      }
      return entry;
    },
    async readSubjectToken(
      sessionId: string,
      issuer: string,
      subject: string,
    ): Promise<HostKvSubjectTokenEntry | undefined> {
      if (!kv || !sessionId) return undefined;
      const handle = kv;
      const prefix = scopePrefix(sessionId, issuer, subject);

      let rawRef: JsonValue | undefined;
      try {
        rawRef = await handle.get(refKey(prefix));
      } catch {
        return undefined;
      }
      const ref = parseRefRecord(rawRef);
      if (!ref) return undefined;

      const immutableKey = entryKey(prefix, ref.id);
      let rawEntry: JsonValue | undefined;
      try {
        rawEntry = await handle.get(immutableKey);
      } catch {
        return undefined;
      }
      const entry = parseEntryRecord(rawEntry);
      if (!entry) return undefined;

      const nowSec = nowSeconds();
      if (ref.exp <= nowSec || entry.exp <= nowSec) {
        await safeDelete(handle, immutableKey);
        return undefined;
      }
      return { id: ref.id, token: entry.token, exp: entry.exp };
    },
    async publishSubjectToken(
      sessionId: string,
      issuer: string,
      subject: string,
      token: string,
      exp: number,
    ): Promise<void> {
      if (!kv || !sessionId) return;
      if (typeof exp !== "number" || !Number.isFinite(exp) || exp <= nowSeconds()) return;
      const prefix = scopePrefix(sessionId, issuer, subject);
      const previous = pendingPublishes.get(prefix) ?? Promise.resolve();
      const current = previous.then(async () => {
        if (!kv) return;
        const handle = kv;
        try {
          const nowSec = nowSeconds();
          if (exp <= nowSec) return;
          const existingRef = parseRefRecord(await handle.get(refKey(prefix)));
          if (existingRef && existingRef.exp > nowSec) {
            const currentEntry = parseEntryRecord(
              await handle.get(entryKey(prefix, existingRef.id)),
            );
            if (currentEntry && currentEntry.exp > nowSec && exp <= currentEntry.exp) {
              return;
            }
          }

          const existingList = parseListRecord(await handle.get(listKey(prefix)));
          const nowForList = nowSeconds();
          const liveEntries: KvRefRecord[] = [];
          const expiredIds = new Set<string>();
          for (const item of existingList) {
            if (item.exp <= nowForList) {
              expiredIds.add(item.id);
            } else {
              liveEntries.push(item);
            }
          }

          const entryId = randomUUID();
          const nextList: KvRefRecord[] = [...liveEntries, { id: entryId, exp }];

          await handle.put(listKey(prefix), {
            entries: nextList.map((item) => ({ id: item.id, exp: item.exp })),
          });

          for (const expiredId of expiredIds) {
            await safeDelete(handle, entryKey(prefix, expiredId));
          }

          await handle.put(entryKey(prefix, entryId), {
            id: entryId,
            token,
            exp,
          });

          await handle.put(refKey(prefix), {
            id: entryId,
            exp,
          });
        } catch {
          // Publication is best-effort; the live local bearer remains usable.
        }
      });

      pendingPublishes.set(prefix, current);
      try {
        await current;
      } finally {
        if (pendingPublishes.get(prefix) === current) {
          pendingPublishes.delete(prefix);
        }
      }
    },
  };
}

/** The default store, shared by `keycardAuth` and the connection factories. */
export const defaultSubjectTokenStore: SubjectTokenStore = memorySubjectTokenStore();

/**
 * The store key for one principal: the zone that issued it and its subject.
 *
 * `keycardAuth` projects `iss` onto `attributes`, so the verifier and the
 * connection factories compute the same key from the `AuthContext` alone.
 */
export function principalKey(auth: Pick<AuthContext, "principalId" | "attributes">): string {
  return `${auth.attributes?.iss ?? ""}|${auth.principalId}`;
}

/**
 * The retained subject token for a session principal, if any. Read from the
 * store only: a value on `session.auth.attributes` is caller-controlled and
 * persisted, so it is never a token.
 */
export function readSubjectToken(
  auth: AuthContext,
  store: SubjectTokenStore,
): string | undefined {
  return store.get(principalKey(auth));
}

function nowSeconds(): number {
  return Date.now() / 1000;
}

function tokenExpired(token: string, nowSec = nowSeconds()): boolean {
  const claims = decodeClaims(token);
  if (claims === null) return false;
  const exp = claims.exp;
  return typeof exp === "number" && Number.isFinite(exp) && exp <= nowSec;
}

function isLocalEntryExpired(entry: LocalSubjectTokenEntry, nowSec: number): boolean {
  if (entry.exp !== undefined) {
    return !Number.isFinite(entry.exp) || entry.exp <= nowSec;
  }
  return tokenExpired(entry.token, nowSec);
}

function scopePrefix(sessionId: string, issuer: string, subject: string): string {
  const digest = createHash("sha256")
    .update(JSON.stringify([sessionId, issuer, subject]))
    .digest("hex");
  return `keycard:subject-token:v1:${digest}`;
}

function listKey(prefix: string): string {
  return `${prefix}:list`;
}

function refKey(prefix: string): string {
  return `${prefix}:ref`;
}

function entryKey(prefix: string, id: string): string {
  return `${prefix}:entry:${id}`;
}

function parseRefRecord(value: JsonValue | undefined): KvRefRecord | undefined {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
  const id = (value as Record<string, unknown>).id;
  const exp = (value as Record<string, unknown>).exp;
  if (typeof id !== "string" || !id || typeof exp !== "number" || !Number.isFinite(exp)) {
    return undefined;
  }
  return { id, exp };
}

function parseEntryRecord(value: JsonValue | undefined): KvEntryRecord | undefined {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
  const id = (value as Record<string, unknown>).id;
  const token = (value as Record<string, unknown>).token;
  const exp = (value as Record<string, unknown>).exp;
  if (
    typeof id !== "string" ||
    !id ||
    typeof token !== "string" ||
    !token ||
    typeof exp !== "number" ||
    !Number.isFinite(exp)
  ) {
    return undefined;
  }
  return { id, token, exp };
}

function parseListRecord(value: JsonValue | undefined): KvRefRecord[] {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return [];
  const entries = (value as Record<string, unknown>).entries;
  if (!Array.isArray(entries)) return [];
  const result: KvRefRecord[] = [];
  for (const item of entries) {
    const parsed = parseRefRecord(item as JsonValue);
    if (parsed) result.push(parsed);
  }
  return result;
}

async function safeDelete(handle: HostKvApi, key: string): Promise<void> {
  try {
    await handle.delete(key);
  } catch {
    // Cleanup is best-effort.
  }
}
