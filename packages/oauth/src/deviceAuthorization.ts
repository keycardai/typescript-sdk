import { requestSignal } from "./requestSignal.js";
import { requireClientAuthentication, type ApplicationCredential, type ClientAuthenticator } from "./credentials.js";
import { fetchAuthorizationServerMetadata, type OAuthAuthorizationServerMetadata } from "./discovery.js";
import { ConfigurationError, DeviceGrantError, DevicePollError, HTTPError } from "./errors.js";
import { deserializeTokenResponse, type TokenResponse } from "./tokenExchange.js";

// =============================================================================
// Device Authorization Grant (RFC 8628), device side
// =============================================================================

const DEVICE_CODE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code";
const DEFAULT_INTERVAL_SECONDS = 5;
const SLOW_DOWN_INCREMENT_SECONDS = 5;

/**
 * The time source and timer for the device grant. Inject a fake in tests so
 * that `expiresAt` and the waits between polls do not depend on real time.
 */
export interface Clock {
  /** The current time in milliseconds since the Unix epoch. */
  now(): number;
  /** Resolves after `ms` milliseconds. Rejects with `signal.reason` when `signal` aborts. */
  sleep(ms: number, signal?: AbortSignal): Promise<void>;
}

/** The real clock: `Date.now` and `setTimeout`. */
export const systemClock: Clock = {
  now: () => Date.now(),
  sleep: (ms, signal) =>
    new Promise<void>((resolve, reject) => {
      if (signal?.aborted) {
        reject(signal.reason);
        return;
      }
      const onAbort = () => {
        clearTimeout(timer);
        reject(signal?.reason);
      };
      const timer = setTimeout(() => {
        signal?.removeEventListener("abort", onAbort);
        resolve();
      }, ms);
      signal?.addEventListener("abort", onAbort, { once: true });
    }),
};

/**
 * Options every device grant operation shares. Set exactly one of
 * `credential` and `clientId`, and use the same one for every operation in
 * a flow: the zone binds the device code to the client and how it
 * authenticated.
 */
export interface DeviceClientOptions {
  /**
   * Authenticates each request with the credential's `clientAuthentication`,
   * called once per request with the URL of the endpoint the request goes
   * to. A credential without `clientAuthentication` throws
   * `ConfigurationError` before any request.
   */
  credential?: ApplicationCredential;
  /** Public client. Sent as `client_id` in the body, with no other authentication. */
  clientId?: string;
  /** Pre-discovered metadata. When set, no discovery request is made. */
  metadata?: OAuthAuthorizationServerMetadata;
  signal?: AbortSignal;
  /** Timeout in milliseconds for each request to the authorization server (default 10 seconds; 0 disables). */
  timeoutMs?: number;
}

export interface RequestDeviceAuthorizationOptions extends DeviceClientOptions {
  /** Sent as one space-joined `scope` parameter. */
  scopes?: readonly string[];
  /** RFC 8707 resource indicators, sent as one `resource` parameter each. */
  resources?: readonly string[];
  /** Sets `expiresAt`. Default: `systemClock`. */
  clock?: Clock;
}

/**
 * The device authorization response (RFC 8628 §3.2). A plain value: the
 * caller may persist it and poll from another process that authenticates as
 * the same client.
 */
export interface DeviceAuthorization {
  /** The code the device polls with. NEVER show it to the person. */
  deviceCode: string;
  /** The code the person confirms. Always show it, so the person can compare it with the confirmation page. */
  userCode: string;
  /** Where the person enters `userCode`. */
  verificationUri: string;
  /** `verificationUri` with `userCode` filled in. Show it in place of `verificationUri` when it is set. */
  verificationUriComplete?: string;
  /** Lifetime of `deviceCode` and `userCode`, in seconds. */
  expiresIn: number;
  /** Minimum wait between polls, in seconds. 5 when the response omits it. */
  interval: number;
  /** The time the response was received plus `expiresIn`, in milliseconds since the Unix epoch, read from the clock. */
  expiresAt: number;
}

export interface PollDeviceTokenOptions extends DeviceClientOptions {
  /** The response from `requestDeviceAuthorization`. `pollDeviceToken` reads only `deviceCode`. */
  authorization: DeviceAuthorization;
}

export interface WaitForDeviceTokenOptions extends PollDeviceTokenOptions {
  /**
   * The wait in seconds before the first poll, and the starting interval.
   * Default: `authorization.interval`. To resume after a `DevicePollError`,
   * pass its `interval`. A value below `authorization.interval` throws
   * `ConfigurationError`.
   */
  interval?: number;
  /** Reads the time for the expiry check and waits between polls. Default: `systemClock`. */
  clock?: Clock;
}

/**
 * Ask the zone for a device code and a user code (RFC 8628 §3.1).
 *
 * The SDK does not deliver the user code. Show the person
 * `verificationUriComplete` when it is set, and `verificationUri`
 * otherwise, together with `userCode`.
 *
 * Throws `ConfigurationError` before any request when the client options
 * are not exactly one of `credential` and `clientId`, or when the credential
 * has no `clientAuthentication`. Throws `ConfigurationError` before the
 * device authorization request when the metadata has no
 * `device_authorization_endpoint`. An OAuth error response throws
 * `DeviceGrantError`, and a response missing a required field throws
 * `DeviceGrantError` with code `invalid_response`.
 */
export async function requestDeviceAuthorization(
  issuer: string,
  options: RequestDeviceAuthorizationOptions = {},
): Promise<DeviceAuthorization> {
  const client = resolveClient(options, "requestDeviceAuthorization");
  const metadata = await resolveMetadata(issuer, options);
  const endpoint = metadata.device_authorization_endpoint;
  if (!endpoint) {
    throw new ConfigurationError(
      `Authorization server "${issuer}" does not advertise a device_authorization_endpoint`,
    );
  }

  const params = new URLSearchParams();
  if (options.scopes && options.scopes.length > 0) {
    params.set("scope", options.scopes.join(" "));
  }
  for (const resource of options.resources ?? []) {
    params.append("resource", resource);
  }

  const response = await unwrapTransport(post(issuer, endpoint, params, client, options));
  if (!response.ok) {
    throw await errorFromResponse(response, "Device authorization request");
  }
  const json = await readJsonObject(response);
  return parseDeviceAuthorization(json, response.status, options.clock ?? systemClock);
}

/**
 * Poll the token endpoint once (RFC 8628 §3.4) with
 * `authorization.deviceCode`. Returns the token once the person approves.
 *
 * An OAuth error response throws `DeviceGrantError` with the server's code,
 * including `authorization_pending` and `slow_down`. A non-2xx response
 * without an OAuth error body throws `HTTPError`. A network failure or
 * timeout throws the platform's error unchanged.
 */
export async function pollDeviceToken(
  issuer: string,
  options: PollDeviceTokenOptions,
): Promise<TokenResponse> {
  const client = resolveClient(options, "pollDeviceToken");
  requireDeviceCode(options.authorization);
  const tokenEndpoint = requireTokenEndpoint(issuer, await resolveMetadata(issuer, options));
  return unwrapTransport(poll(issuer, tokenEndpoint, client, options));
}

/**
 * Poll until the person approves or denies the request, following
 * RFC 8628 §3.5.
 *
 * - It waits the interval before each poll, including the first.
 * - On `authorization_pending` it polls again.
 * - On `slow_down` it adds 5 seconds to the interval for this poll and every later one.
 * - On any other OAuth error it stops and throws that `DeviceGrantError`.
 * - On a network error, a timeout, an HTTP 5xx, or an HTTP 429 it stops and
 *   throws `DevicePollError`. It does not poll again.
 * - If the next poll would start after `authorization.expiresAt`, it stops
 *   without waiting or polling and throws `DeviceGrantError` with code
 *   `expired_token`.
 *
 * Polling again on `authorization_pending` and `slow_down` is the grant
 * itself, not a retry. `timeoutMs` bounds each request, not the waits or the
 * whole loop. Aborting `signal` ends the wait or the request in progress and
 * rejects with `signal.reason`. No request is sent after the abort.
 *
 * When the device authorization request named more than one resource, the
 * token is not for any one of them. NEVER store it as the token for one
 * resource. To get a token for one resource, call `refreshAuthorization`
 * with `resources` set to it.
 */
export async function waitForDeviceToken(
  issuer: string,
  options: WaitForDeviceTokenOptions,
): Promise<TokenResponse> {
  const client = resolveClient(options, "waitForDeviceToken");
  const { authorization, signal } = options;
  requireDeviceCode(authorization);
  if (!Number.isFinite(authorization.expiresAt)) {
    throw new ConfigurationError("waitForDeviceToken: the device authorization has no expiresAt");
  }
  const minimum = authorization.interval > 0 ? authorization.interval : DEFAULT_INTERVAL_SECONDS;
  let interval = minimum;
  if (options.interval !== undefined) {
    if (!Number.isFinite(options.interval) || options.interval < minimum) {
      throw new ConfigurationError(
        `waitForDeviceToken: interval ${options.interval} is below the device authorization interval ${minimum}`,
      );
    }
    interval = options.interval;
  }
  const clock = options.clock ?? systemClock;

  signal?.throwIfAborted();
  const tokenEndpoint = requireTokenEndpoint(issuer, await resolveMetadata(issuer, options));

  for (;;) {
    if (clock.now() + interval * 1000 > authorization.expiresAt) {
      throw new DeviceGrantError("expired_token", {
        errorDescription: "The device code expired before the request was approved",
      });
    }
    await clock.sleep(interval * 1000, signal);
    signal?.throwIfAborted();

    try {
      return await poll(issuer, tokenEndpoint, client, options);
    } catch (error) {
      signal?.throwIfAborted();
      if (error instanceof TransportFailure) {
        throw new DevicePollError(interval, error.cause);
      }
      if ((error instanceof DeviceGrantError || error instanceof HTTPError) && isTransientStatus(error.status)) {
        throw new DevicePollError(interval, error);
      }
      if (error instanceof DeviceGrantError && error.errorCode === "authorization_pending") {
        continue;
      }
      if (error instanceof DeviceGrantError && error.errorCode === "slow_down") {
        interval += SLOW_DOWN_INCREMENT_SECONDS;
        continue;
      }
      throw error;
    }
  }
}

// =============================================================================
// Internals
// =============================================================================

type DeviceClient = { credential: ClientAuthenticator } | { clientId: string };

/** A fetch that failed before a response arrived: a network error or a timeout. */
class TransportFailure {
  constructor(readonly cause: unknown) {}
}

function resolveClient(options: DeviceClientOptions, operation: string): DeviceClient {
  const { credential, clientId } = options;
  if (credential && !clientId) {
    return { credential: requireClientAuthentication(credential, operation) };
  }
  if (clientId && !credential) {
    return { clientId };
  }
  throw new ConfigurationError(`${operation}: set exactly one of credential and clientId`);
}

function requireDeviceCode(authorization: DeviceAuthorization | undefined): void {
  if (!authorization || typeof authorization.deviceCode !== "string" || !authorization.deviceCode) {
    throw new ConfigurationError("the device authorization has no deviceCode");
  }
}

function requireTokenEndpoint(issuer: string, metadata: OAuthAuthorizationServerMetadata): string {
  if (!metadata.token_endpoint) {
    throw new ConfigurationError(`Authorization server "${issuer}" does not advertise a token_endpoint`);
  }
  return metadata.token_endpoint;
}

async function resolveMetadata(
  issuer: string,
  options: DeviceClientOptions,
): Promise<OAuthAuthorizationServerMetadata> {
  return options.metadata
    ?? fetchAuthorizationServerMetadata(issuer, { signal: options.signal, timeoutMs: options.timeoutMs });
}

function isTransientStatus(status: number | undefined): boolean {
  return status !== undefined && (status >= 500 || status === 429);
}

async function unwrapTransport<T>(promise: Promise<T>): Promise<T> {
  try {
    return await promise;
  } catch (error) {
    throw error instanceof TransportFailure ? error.cause : error;
  }
}

/** One device token poll. Throws `TransportFailure` when no response arrives. */
async function poll(
  issuer: string,
  tokenEndpoint: string,
  client: DeviceClient,
  options: PollDeviceTokenOptions,
): Promise<TokenResponse> {
  const params = new URLSearchParams();
  params.set("grant_type", DEVICE_CODE_GRANT_TYPE);
  params.set("device_code", options.authorization.deviceCode);

  const response = await post(issuer, tokenEndpoint, params, client, options);
  if (!response.ok) {
    throw await errorFromResponse(response, "Device token poll");
  }
  const json = await readJsonObject(response);
  try {
    return deserializeTokenResponse(json);
  } catch (error) {
    throw new DeviceGrantError("invalid_response", {
      errorDescription: error instanceof Error ? error.message : String(error),
      status: response.status,
    });
  }
}

/**
 * POSTs `params` to `endpoint` with the client authentication added. Errors
 * from the credential are thrown unchanged. A fetch failure is thrown as
 * `TransportFailure`.
 */
async function post(
  issuer: string,
  endpoint: string,
  params: URLSearchParams,
  client: DeviceClient,
  options: DeviceClientOptions,
): Promise<Response> {
  const headers: Record<string, string> = {};
  if ("credential" in client) {
    const auth = await client.credential.clientAuthentication(issuer, endpoint);
    Object.assign(headers, auth.headers);
    for (const [name, value] of Object.entries(auth.form)) params.set(name, value);
  } else {
    params.set("client_id", client.clientId);
  }
  headers["Content-Type"] = "application/x-www-form-urlencoded";
  options.signal?.throwIfAborted();

  try {
    return await fetch(endpoint, {
      method: "POST",
      headers,
      body: params.toString(),
      signal: requestSignal(options.signal, options.timeoutMs),
    });
  } catch (cause) {
    throw new TransportFailure(cause);
  }
}

/** A `DeviceGrantError` for an RFC 6749 §5.2 error body, an `HTTPError` otherwise. */
async function errorFromResponse(response: Response, what: string): Promise<DeviceGrantError | HTTPError> {
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    body = undefined;
  }
  if (body && typeof body === "object" && !Array.isArray(body)) {
    const fields = body as Record<string, unknown>;
    if (typeof fields.error === "string" && fields.error) {
      return new DeviceGrantError(fields.error, {
        errorDescription: typeof fields.error_description === "string" ? fields.error_description : undefined,
        errorUri: typeof fields.error_uri === "string" ? fields.error_uri : undefined,
        status: response.status,
      });
    }
  }
  return new HTTPError(`${what} failed (HTTP ${response.status})`, response.status);
}

async function readJsonObject(response: Response): Promise<Record<string, unknown>> {
  let json: unknown;
  try {
    json = await response.json();
  } catch {
    json = undefined;
  }
  if (!json || typeof json !== "object" || Array.isArray(json)) {
    throw new DeviceGrantError("invalid_response", {
      errorDescription: "Response is not a JSON object",
      status: response.status,
    });
  }
  return json as Record<string, unknown>;
}

function parseDeviceAuthorization(json: Record<string, unknown>, status: number, clock: Clock): DeviceAuthorization {
  const missing: string[] = [];
  const text = (name: string): string => {
    const value = json[name];
    if (typeof value === "string" && value) return value;
    missing.push(name);
    return "";
  };
  const deviceCode = text("device_code");
  const userCode = text("user_code");
  const verificationUri = text("verification_uri");
  const expiresIn = json.expires_in;
  if (typeof expiresIn !== "number" || !(expiresIn > 0)) missing.push("expires_in");
  if (missing.length > 0) {
    throw new DeviceGrantError("invalid_response", {
      errorDescription: `Device authorization response is missing ${missing.join(", ")}`,
      status,
    });
  }

  const authorization: DeviceAuthorization = {
    deviceCode,
    userCode,
    verificationUri,
    expiresIn: expiresIn as number,
    interval: typeof json.interval === "number" && json.interval > 0 ? json.interval : DEFAULT_INTERVAL_SECONDS,
    expiresAt: clock.now() + (expiresIn as number) * 1000,
  };
  if (typeof json.verification_uri_complete === "string" && json.verification_uri_complete) {
    authorization.verificationUriComplete = json.verification_uri_complete;
  }
  return authorization;
}
