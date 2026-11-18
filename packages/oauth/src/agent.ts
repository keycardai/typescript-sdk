import * as http from "node:http";
import * as path from "node:path";
import type { Clock } from "./deviceAuthorization.js";
import { systemClock } from "./deviceAuthorization.js";
import {
  AgentError,
  AgentResponseError,
  ConfigurationError,
  HTTPError,
  NetworkError,
} from "./errors.js";
import type { TokenResponse } from "./tokenExchange.js";

export {
  AgentError,
  AgentErrorCode,
  AgentResponseError,
  NetworkError,
  isApplicationNotFound,
  isAuthorizationRequired,
  isDeclined,
  isPrompterUnavailable,
  isRateLimited,
  isUnavailable,
} from "./errors.js";

/**
 * Anything that answers "a token for resource X with scopes S".
 * {@link AgentTokenSource} is the implementation over the local Keycard agent.
 */
export interface ResourceTokenSource {
  resourceToken(resource: string, options?: ResourceTokenOptions): Promise<TokenResponse>;
}

export interface ResourceTokenOptions {
  /** Scopes requested alongside the resource, sent as given. Default: none. */
  scopes?: readonly string[];
  /**
   * Aborts the call. Nothing else bounds it: the first request for an
   * approval waits for as long as the human takes to answer the prompt.
   */
  signal?: AbortSignal;
}

export interface AgentTokenSourceOptions {
  /**
   * Path of the agent's Unix socket. Default: `KEYCARD_SOCKET` in `env`, else
   * the `keycard agent` daemon's default socket.
   */
  socket?: string;
  /**
   * Where `KEYCARD_SOCKET` and the variables locating the default socket are
   * read from, on every call. Default: `process.env`.
   */
  env?: Readonly<Record<string, string | undefined>>;
  /** Name shown to the human in the approval prompt. Self-declared and unauthenticated. */
  workload?: string;
  /**
   * Identifier of the Keycard application the caller says it acts for, as set
   * on the application, not its public id. Self-declared and unauthenticated.
   */
  appId?: string;
  /** Organization id. Needed by the multi-zone daemon; ignored by a `keycard run` server. */
  org?: string;
  /** Zone id, set alongside `org`. */
  zone?: string;
  /** Reads the time `expiresIn` is computed against. Default: `systemClock`. */
  clock?: Pick<Clock, "now">;
}

const ISSUE_TOKEN_PATH = "/keycard.agent.v1.AgentService/IssueToken";
const MAX_ERROR_BODY_BYTES = 64 * 1024;

type SocketRule = "option" | "env" | "default";

interface ResolvedSocket {
  path: string;
  rule: SocketRule;
}

/**
 * A {@link ResourceTokenSource} that asks the Keycard agent on this machine
 * (`keycard run`'s per-session server, or the `keycard agent` daemon) to
 * issue the token, over its Unix socket. The application holds no
 * credential; the agent asks a human to approve each new request.
 *
 * Construction opens no connection and resolves nothing. Every
 * `resourceToken` call resolves the socket and sends one `IssueToken`
 * request; the agent caches tokens, this class does not.
 *
 * **Requires Node.js** (Unix domain sockets).
 */
export class AgentTokenSource implements ResourceTokenSource {
  #socket?: string;
  #env?: Readonly<Record<string, string | undefined>>;
  #workload: string;
  #appId?: string;
  #org?: string;
  #zone?: string;
  #clock: Pick<Clock, "now">;

  constructor(options?: AgentTokenSourceOptions) {
    this.#socket = options?.socket;
    this.#env = options?.env;
    this.#workload = options?.workload ?? "";
    this.#appId = options?.appId;
    this.#org = options?.org;
    this.#zone = options?.zone;
    this.#clock = options?.clock ?? systemClock;
  }

  /**
   * Asks the agent for a token for `resource` carrying `options.scopes`.
   *
   * Throws {@link ConfigurationError} for an empty resource or an
   * unresolvable socket, {@link NetworkError} when the agent cannot be
   * reached, {@link AgentError} when the agent refuses,
   * {@link AgentResponseError} for an unusable 200 response, and
   * {@link HTTPError} for any other non-200 response. Rejects with
   * `options.signal.reason` when the signal aborts.
   */
  async resourceToken(resource: string, options?: ResourceTokenOptions): Promise<TokenResponse> {
    if (!resource) {
      throw new ConfigurationError("AgentTokenSource: resource is required");
    }
    const socket = resolveSocket(this.#socket, this.#env ?? process.env);

    const body: Record<string, unknown> = {
      resource,
      scopes: options?.scopes ? [...options.scopes] : [],
      workload: this.#workload,
    };
    // An agent that predates appId drops it, and an empty value is not a declaration.
    if (this.#appId) body.appId = this.#appId;

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      "Connect-Protocol-Version": "1",
    };
    if (this.#org) headers["Keycard-Org"] = this.#org;
    if (this.#zone) headers["Keycard-Zone"] = this.#zone;

    const response = await post(socket, headers, JSON.stringify(body), options?.signal);
    if (response.status !== 200) {
      throw errorFromResponse(response);
    }
    return this.#parseToken(response.body);
  }

  #parseToken(body: string): TokenResponse {
    let json: unknown;
    try {
      json = JSON.parse(body);
    } catch {
      throw new AgentResponseError("Keycard agent response is not JSON");
    }
    if (typeof json !== "object" || json === null || Array.isArray(json)) {
      throw new AgentResponseError("Keycard agent response is not a JSON object");
    }
    const { token, expiresAt, scopes } = json as Record<string, unknown>;

    if (typeof token !== "string" || !token) {
      throw new AgentResponseError("Keycard agent response has no token");
    }
    // The token may be an opaque third-party secret headed for an Authorization header.
    if (/[\x00-\x1f\x7f]/.test(token)) {
      throw new AgentResponseError("Keycard agent token contains a control character");
    }

    const result: TokenResponse = { accessToken: token, tokenType: "Bearer" };
    if (expiresAt !== undefined && expiresAt !== null) {
      const expiresAtMs = typeof expiresAt === "string" ? parseRFC3339(expiresAt) : undefined;
      if (expiresAtMs === undefined) {
        throw new AgentResponseError("Keycard agent response has an unparseable expiresAt");
      }
      result.expiresIn = Math.max(0, Math.floor((expiresAtMs - this.#clock.now()) / 1000));
    }
    if (Array.isArray(scopes) && scopes.length > 0 && scopes.every((s) => typeof s === "string")) {
      result.scope = scopes as string[];
    }
    return result;
  }
}

export interface ResourceTransportOptions {
  /** Mints the token. Required. */
  source: ResourceTokenSource;
  /** The resource indicator every request is authorized against. Required. */
  resource: string;
  /** Requested alongside `resource`. */
  scopes?: readonly string[];
  /** The `fetch` the authorized request is sent with. Default: the global `fetch`. */
  fetch?: typeof fetch;
}

/**
 * Returns a `fetch`-compatible function that sets
 * `Authorization: Bearer <token>` on every request, replacing any existing
 * value, with a token from `source` for `resource`. The resource is fixed,
 * never derived from the request URL: use one transport per resource.
 *
 * The caller's `Request` and `init` are not modified. An error from the
 * source propagates as thrown, so the agent predicates apply to it, and the
 * request is not sent. The transport adds no timeout; `init.signal` bounds
 * both the token and the request.
 *
 * Throws {@link ConfigurationError} when `source` or `resource` is missing.
 */
export function resourceTransport(options: ResourceTransportOptions): typeof fetch {
  if (!options?.source) {
    throw new ConfigurationError("resourceTransport: source is required");
  }
  if (!options.resource) {
    throw new ConfigurationError("resourceTransport: resource is required");
  }
  const { source, resource, scopes } = options;

  return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const signal = init?.signal ?? (input instanceof Request ? input.signal : undefined);
    const token = await source.resourceToken(resource, { scopes, signal: signal ?? undefined });

    // init.headers, when given, replaces the Request's headers, as fetch does.
    const headers = new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined));
    headers.set("Authorization", `Bearer ${token.accessToken}`);
    return (options.fetch ?? fetch)(input, { ...init, headers });
  };
}

function resolveSocket(
  socket: string | undefined,
  env: Readonly<Record<string, string | undefined>>,
): ResolvedSocket {
  if (socket) return { path: socket, rule: "option" };

  const get = (name: string): string | undefined => env[name] || undefined;

  const fromEnv = get("KEYCARD_SOCKET");
  if (fromEnv) return { path: fromEnv, rule: "env" };

  if (process.platform === "win32") {
    throw new ConfigurationError(
      "No Keycard agent socket: set KEYCARD_SOCKET or pass socket. " +
        "The keycard agent daemon's default socket is a Unix socket and is not available on Windows.",
    );
  }
  return { path: path.join(defaultAgentDir(get), "agent.sock"), rule: "default" };
}

// Transcribes the Keycard CLI's Config.AgentSocketPath and runDir
// (config_unix.go) and xdgDir (config.go), minus their keycard.toml
// fallbacks and their directory creation.
function defaultAgentDir(get: (name: string) => string | undefined): string {
  const agentDir = get("KEYCARD_AGENT_DIR");
  if (agentDir) return agentDir;

  const runtimeDir = get("XDG_RUNTIME_DIR");
  if (runtimeDir) return path.join(runtimeDir, "keycard");

  const stateHome = get("XDG_STATE_HOME");
  if (stateHome) return path.join(stateHome, "keycard", "run");

  const home = get("KEYCARD_HOME") ?? get("HOME");
  if (!home) {
    throw new ConfigurationError(
      "No Keycard agent socket: KEYCARD_SOCKET is not set, and neither is HOME (or KEYCARD_HOME) " +
        "to locate the keycard agent daemon's default socket. Set KEYCARD_SOCKET or pass socket.",
    );
  }
  return path.join(home, ".local", "state", "keycard", "run");
}

function describeSocket({ path: socketPath, rule }: ResolvedSocket): string {
  switch (rule) {
    case "option":
      return `${socketPath} (from the socket option)`;
    case "env":
      return `${socketPath} (from KEYCARD_SOCKET)`;
    case "default":
      return `${socketPath} (the keycard agent daemon's default socket, as KEYCARD_SOCKET is not set)`;
  }
}

function networkError(socket: ResolvedSocket, cause: unknown): NetworkError {
  let message = `Cannot reach the Keycard agent at ${describeSocket(socket)}`;
  if (cause instanceof Error && cause.message) message += `: ${cause.message}`;
  if (socket.rule === "default") {
    message += ". Start the daemon with `keycard agent start`, or run this program under `keycard run`.";
  }
  return new NetworkError(message, { cause });
}

interface AgentResponse {
  status: number;
  body: string;
}

function post(
  socket: ResolvedSocket,
  headers: Record<string, string>,
  payload: string,
  signal: AbortSignal | undefined,
): Promise<AgentResponse> {
  return new Promise<AgentResponse>((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason);
      return;
    }
    let settled = false;
    const settle = (fn: () => void) => {
      if (settled) return;
      settled = true;
      signal?.removeEventListener("abort", onAbort);
      fn();
    };
    const onAbort = () => {
      settle(() => reject(signal?.reason));
      request.destroy();
    };

    const request = http.request(
      {
        socketPath: socket.path,
        // The host is a placeholder the agent does not interpret.
        host: "localhost",
        path: ISSUE_TOKEN_PATH,
        method: "POST",
        headers: { ...headers, "Content-Length": Buffer.byteLength(payload) },
      },
      (response) => {
        const status = response.statusCode ?? 0;
        const limit = status === 200 ? Infinity : MAX_ERROR_BODY_BYTES;
        const chunks: Buffer[] = [];
        let size = 0;
        const finish = () =>
          settle(() => resolve({ status, body: Buffer.concat(chunks).subarray(0, limit).toString("utf-8") }));
        response.on("data", (chunk: Buffer) => {
          chunks.push(chunk);
          size += chunk.length;
          if (size >= limit) {
            finish();
            response.destroy();
          }
        });
        response.on("end", finish);
        response.on("error", (error) => settle(() => reject(networkError(socket, error))));
        response.on("aborted", () =>
          settle(() => reject(networkError(socket, new Error("connection closed mid-response")))),
        );
      },
    );
    request.on("error", (error) => settle(() => reject(networkError(socket, error))));
    signal?.addEventListener("abort", onAbort, { once: true });
    request.end(payload);
  });
}

function errorFromResponse(response: AgentResponse): Error {
  try {
    const json = JSON.parse(response.body) as unknown;
    if (typeof json === "object" && json !== null) {
      const { code, message } = json as Record<string, unknown>;
      if (typeof code === "string" && code) {
        return new AgentError(code, typeof message === "string" ? message : "");
      }
    }
  } catch {
    // Not a Connect error: fall through to the HTTP error.
  }
  return new HTTPError(`Keycard agent returned HTTP ${response.status}`, response.status);
}

const RFC3339 =
  /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(?:([Zz])|([+-])(\d{2}):(\d{2}))$/;

/**
 * Parses an RFC 3339 timestamp with up to nine fractional digits into
 * milliseconds since the epoch. `Date.parse` is not used: it accepts formats RFC 3339 does not, and its
 * handling of more than three fractional digits is implementation-defined.
 */
function parseRFC3339(value: string): number | undefined {
  const match = RFC3339.exec(value);
  if (!match) return undefined;
  const [year, month, day, hour, minute, second] = match.slice(1, 7).map(Number);
  const [frac, z, sign, offsetHours, offsetMinutes] = match.slice(7);
  // RFC 3339 allows a leap second (60), which rolls into the next minute.
  if (month < 1 || month > 12 || hour > 23 || minute > 59 || second > 60) return undefined;
  if (!z && (Number(offsetHours) > 23 || Number(offsetMinutes) > 59)) return undefined;

  const date = new Date(0);
  date.setUTCFullYear(year, month - 1, day);
  if (date.getUTCDate() !== day) return undefined;
  date.setUTCHours(hour, minute, second, 0);

  // Truncated to whole milliseconds: a double near the current epoch cannot
  // hold nanoseconds, and rounding .999999999 up would add a second.
  const fraction = frac ? Number(frac.padEnd(3, "0").slice(0, 3)) : 0;
  const offset = z ? 0 : (sign === "-" ? -1 : 1) * (Number(offsetHours) * 60 + Number(offsetMinutes)) * 60_000;
  return date.getTime() + fraction - offset;
}
