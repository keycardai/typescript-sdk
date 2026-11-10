import { requestSignal } from "./requestSignal.js";
import { requireClientAuthentication, type ApplicationCredential, type ClientAuthenticator } from "./credentials.js";
import { fetchAuthorizationServerMetadata, type OAuthAuthorizationServerMetadata } from "./discovery.js";
import { ConfigurationError, DeviceGrantError, HTTPError, OAuthError } from "./errors.js";
import { deserializeTokenResponse, type TokenResponse } from "./tokenExchange.js";

// =============================================================================
// Device Authorization Grant (RFC 8628), device side
// =============================================================================

const DEVICE_CODE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code";
const DEFAULT_INTERVAL_SECONDS = 5;

/**
 * The time source for the device grant. Inject a fake in tests so that
 * `expiresAt` does not depend on real time.
 */
export interface Clock {
  /** The current time in milliseconds since the Unix epoch. */
  now(): number;
}

/** The real clock: `Date.now`. */
export const systemClock: Clock = {
  now: () => Date.now(),
};

/**
 * Options every device grant operation shares. Set exactly one of
 * `credential` and `clientId`, and use the same one for every operation in
 * a flow: the zone binds the device code to the client and how it
 * authenticated.
 */
export type DeviceClientOptions = (
  | {
      /**
       * Authenticates each request with the credential's
       * `clientAuthentication`, called once per request with the URL of the
       * endpoint the request goes to.
       */
      credential: ApplicationCredential;
      clientId?: never;
    }
  | {
      /** Public client. Sent as `client_id` in the body, with no other authentication. */
      clientId: string;
      credential?: never;
    }
) & {
  /** Pre-discovered metadata. When set, no discovery request is made. */
  metadata?: OAuthAuthorizationServerMetadata;
  /** Aborting it rejects with `signal.reason`. No request is sent after the abort. */
  signal?: AbortSignal;
  /** Timeout in milliseconds for each request to the authorization server (default 10 seconds; 0 disables). */
  timeoutMs?: number;
};

export type RequestDeviceAuthorizationOptions = DeviceClientOptions & {
  /** Sent as one space-joined `scope` parameter. */
  scopes?: readonly string[];
  /** RFC 8707 resource indicators, sent as one `resource` parameter each. */
  resources?: readonly string[];
  /** Sets `expiresAt`. Default: `systemClock`. */
  clock?: Clock;
};

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

export type PollDeviceTokenOptions = DeviceClientOptions & {
  /** The response from `requestDeviceAuthorization`. `pollDeviceToken` reads only `deviceCode`. */
  authorization: DeviceAuthorization;
  /**
   * The zone's metadata. Required: fetch it once with
   * `fetchAuthorizationServerMetadata` and pass it to every poll.
   */
  metadata: OAuthAuthorizationServerMetadata;
};

/**
 * Ask the zone for a device code and a user code (RFC 8628 §3.1).
 *
 * The SDK does not deliver the user code. Show the person
 * `verificationUriComplete` when it is set, and `verificationUri`
 * otherwise, together with `userCode`.
 *
 * Throws `ConfigurationError` before any request when the client options
 * are not exactly one of `credential` and `clientId`, when the credential
 * has no `clientAuthentication`, or when `metadata` is not set and `issuer`
 * is not an http or https URL. Throws `ConfigurationError` before the
 * device authorization request when the metadata has no
 * `device_authorization_endpoint` or it is not an http or https URL. An error
 * from the credential's `clientAuthentication` is thrown as is. Every other
 * failure throws `DeviceGrantError`, including a failed discovery request.
 * A response that is missing a required
 * field, or has an `interval` that is not a positive integer, throws
 * `DeviceGrantError` `invalid_response`.
 */
export async function requestDeviceAuthorization(
  issuer: string,
  options: RequestDeviceAuthorizationOptions,
): Promise<DeviceAuthorization> {
  const client = resolveClient(options, "requestDeviceAuthorization");
  const metadata = await resolveMetadata(issuer, "requestDeviceAuthorization", options);
  const endpoint = requireEndpoint(issuer, metadata, "device_authorization_endpoint");

  const params = new URLSearchParams();
  if (options.scopes && options.scopes.length > 0) {
    params.set("scope", options.scopes.join(" "));
  }
  for (const resource of options.resources ?? []) {
    params.append("resource", resource);
  }

  const what = "Device authorization request";
  return withTransportError(what, options.signal, async () => {
    const response = await post(issuer, endpoint, params, client, options);
    if (!response.ok) {
      throw await errorFromResponse(response, what);
    }
    const json = await readJsonObject(response);
    return parseDeviceAuthorization(json, response.status, options.clock ?? systemClock);
  });
}

/**
 * Poll the token endpoint once (RFC 8628 §3.4) with
 * `authorization.deviceCode`. Returns the token once the person approves.
 *
 * Throws `ConfigurationError` before any request when the client options
 * are not exactly one of `credential` and `clientId`, when `metadata` is
 * missing, or when it has no `token_endpoint` or it is not an http or https
 * URL. An error from the credential's `clientAuthentication` is thrown as
 * is. Every other failure throws `DeviceGrantError`, including
 * `authorization_pending` and `slow_down`.
 *
 * If you call it in your own loop, wait longer after a timeout or other
 * network error (RFC 8628 §3.5).
 */
export async function pollDeviceToken(
  issuer: string,
  options: PollDeviceTokenOptions,
): Promise<TokenResponse> {
  const client = resolveClient(options, "pollDeviceToken");
  requireDeviceCode(options.authorization);
  if (!options.metadata) {
    throw new ConfigurationError("pollDeviceToken: metadata is required");
  }
  const tokenEndpoint = requireEndpoint(issuer, options.metadata, "token_endpoint");
  return withTransportError("Device token poll", options.signal, () =>
    poll(issuer, tokenEndpoint, client, options.authorization, options),
  );
}

// =============================================================================
// Internals
// =============================================================================

type ResolvedClient = { credential: ClientAuthenticator } | { clientId: string };

/**
 * A request that ended without a complete response: a network error or a
 * timeout, while sending the request or while reading the response body.
 */
class TransportFailure {
  constructor(readonly cause: unknown) {}
}

function resolveClient(options: DeviceClientOptions, operation: string): ResolvedClient {
  const { credential, clientId } = options;
  if (credential !== undefined && clientId !== undefined) {
    throw new ConfigurationError(`${operation}: set either credential or clientId, not both`);
  }
  if (credential !== undefined) {
    return { credential: requireClientAuthentication(credential, operation) };
  }
  if (typeof clientId === "string" && clientId) {
    return { clientId };
  }
  throw new ConfigurationError(`${operation}: clientId or credential is required`);
}

function requireDeviceCode(authorization: DeviceAuthorization | undefined): void {
  if (!authorization || typeof authorization.deviceCode !== "string" || !authorization.deviceCode) {
    throw new ConfigurationError("the device authorization has no deviceCode");
  }
}

function requireEndpoint(
  issuer: string,
  metadata: OAuthAuthorizationServerMetadata,
  field: "device_authorization_endpoint" | "token_endpoint",
): string {
  const endpoint = metadata[field];
  if (!endpoint) {
    throw new ConfigurationError(`Authorization server "${issuer}" does not advertise a ${field}`);
  }
  if (!isHttpUrl(endpoint)) {
    throw new ConfigurationError(
      `Authorization server "${issuer}" advertises a ${field} that is not an http or https URL: ${JSON.stringify(endpoint)}`,
    );
  }
  return endpoint;
}

function isHttpUrl(value: string): boolean {
  try {
    const { protocol } = new URL(value);
    return protocol === "https:" || protocol === "http:";
  } catch {
    return false;
  }
}

function isPositiveInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value > 0;
}

/**
 * Returns `options.metadata`, or discovers it. A failed discovery throws
 * `DeviceGrantError` `invalid_response` with the failure as `cause`.
 */
async function resolveMetadata(
  issuer: string,
  operation: string,
  options: DeviceClientOptions,
): Promise<OAuthAuthorizationServerMetadata> {
  if (!options.metadata && !isHttpUrl(issuer)) {
    throw new ConfigurationError(`${operation}: issuer ${JSON.stringify(issuer)} is not an http or https URL`);
  }
  options.signal?.throwIfAborted();
  if (options.metadata) return options.metadata;
  try {
    return await fetchAuthorizationServerMetadata(issuer, { signal: options.signal, timeoutMs: options.timeoutMs });
  } catch (cause) {
    options.signal?.throwIfAborted();
    const detail = cause instanceof Error ? cause.message : String(cause);
    let retryable = !(cause instanceof OAuthError);
    let status: number | undefined;
    if (cause instanceof HTTPError) {
      status = cause.status;
      retryable = isTransientStatus(status);
    }
    throw new DeviceGrantError("invalid_response", {
      errorDescription: `Discovery for "${issuer}" failed: ${detail}`,
      status,
      retryable,
      cause,
    });
  }
}

function isTransientStatus(status: number | undefined): boolean {
  return status !== undefined && (status >= 500 || status === 429);
}

/**
 * Runs `request`. A `TransportFailure` it throws becomes a retryable
 * `DeviceGrantError` with the failure as `cause`. When `signal` has aborted,
 * it rejects with `signal.reason` instead.
 */
async function withTransportError<T>(
  what: string,
  signal: AbortSignal | undefined,
  request: () => Promise<T>,
): Promise<T> {
  try {
    return await request();
  } catch (error) {
    if (!(error instanceof TransportFailure)) throw error;
    signal?.throwIfAborted();
    throw new DeviceGrantError("invalid_response", {
      errorDescription: `${what} failed: ${error.cause instanceof Error ? error.cause.message : String(error.cause)}`,
      retryable: true,
      cause: error.cause,
    });
  }
}

/** One device token poll. Throws `TransportFailure` when no complete response arrives. */
async function poll(
  issuer: string,
  tokenEndpoint: string,
  client: ResolvedClient,
  authorization: DeviceAuthorization,
  options: DeviceClientOptions,
): Promise<TokenResponse> {
  const params = new URLSearchParams();
  params.set("grant_type", DEVICE_CODE_GRANT_TYPE);
  params.set("device_code", authorization.deviceCode);

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
  client: ResolvedClient,
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

/**
 * Reads the body as JSON. Returns `undefined` when the body is not JSON.
 * Throws `TransportFailure` when reading the body fails, such as on a
 * timeout.
 */
async function readJson(response: Response): Promise<unknown> {
  let text: string;
  try {
    text = await response.text();
  } catch (cause) {
    throw new TransportFailure(cause);
  }
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

/**
 * A `DeviceGrantError` with the server's code for an RFC 6749 §5.2 error
 * body. Otherwise a `DeviceGrantError` `invalid_response` that is retryable
 * for a 5xx or 429.
 */
async function errorFromResponse(response: Response, what: string): Promise<DeviceGrantError> {
  const body = await readJson(response);
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
  return new DeviceGrantError("invalid_response", {
    errorDescription: `${what} failed (HTTP ${response.status})`,
    status: response.status,
    retryable: isTransientStatus(response.status),
  });
}

async function readJsonObject(response: Response): Promise<Record<string, unknown>> {
  const json = await readJson(response);
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
  const interval = "interval" in json ? json.interval : DEFAULT_INTERVAL_SECONDS;
  if (!isPositiveInteger(interval)) {
    throw new DeviceGrantError("invalid_response", {
      errorDescription: `Device authorization response interval ${JSON.stringify(interval)} is not a positive integer`,
      status,
    });
  }

  const authorization: DeviceAuthorization = {
    deviceCode,
    userCode,
    verificationUri,
    expiresIn: expiresIn as number,
    interval,
    expiresAt: clock.now() + (expiresIn as number) * 1000,
  };
  if (typeof json.verification_uri_complete === "string" && json.verification_uri_complete) {
    authorization.verificationUriComplete = json.verification_uri_complete;
  }
  return authorization;
}
