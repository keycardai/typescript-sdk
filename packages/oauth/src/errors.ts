export class HTTPError extends Error {
  constructor(
    message: string,
    /** HTTP status of the failed response, when one was received. */
    public readonly status?: number,
  ) {
    super(message);
  }
}

export class BadRequestError extends HTTPError {
}

export class UnauthorizedError extends HTTPError {
}

export class OAuthError extends Error {
  constructor(
    public readonly errorCode: string,
    message: string,
    public readonly errorUri?: string
  ) {
    super(message);
  }
}

export class InvalidTokenError extends OAuthError {
  constructor(message: string, errorUri?: string) {
    super("invalid_token", message, errorUri);
  }
}

export class InsufficientScopeError extends OAuthError {
  constructor(message: string, errorUri?: string) {
    super("insufficient_scope", message, errorUri);
  }
}

/**
 * The authorization server returned an `error` on the redirect instead of a
 * code: the user denied consent, or the request was rejected
 * (RFC 6749 §4.1.2.1). No token request is made.
 */
export class AuthorizationDeniedError extends OAuthError {
  constructor(errorCode: string, public readonly errorDescription?: string, errorUri?: string) {
    super(errorCode, errorDescription ?? `Authorization denied: ${errorCode}`, errorUri);
    this.name = "AuthorizationDeniedError";
  }
}

/**
 * OAuth error codes that no retry can change. An authorization-server error
 * with one of these codes is not retryable, unless it arrives on an HTTP 429
 * or 5xx. The status decides first: a 429 or 5xx is retryable whatever its
 * error code. Use it to classify an error code that arrives without its
 * typed error, such as one read back from a queue or a log.
 */
export const PERMANENT_ERROR_CODES: readonly string[] = Object.freeze([
  "access_denied",
  "expired_token",
  "insufficient_authorization",
  "invalid_client",
]);

/** Reports whether `errorCode` is in `PERMANENT_ERROR_CODES`. */
export function isPermanentErrorCode(errorCode: string): boolean {
  return PERMANENT_ERROR_CODES.includes(errorCode);
}

/**
 * A refresh-token grant was not renewed. `errorCode` is the authorization
 * server's `error` when it returned one (`invalid_grant` means the refresh
 * token is expired, revoked, or was issued to another client, and the only
 * recovery is to authorize again), `invalid_response` otherwise. `retryable`
 * is `true` for a transport failure, HTTP 5xx, or 429, whatever the error
 * code, and `false` for every other 4xx. `cause` holds the underlying error
 * for a transport failure.
 */
export class RefreshGrantError extends OAuthError {
  readonly retryable: boolean;
  readonly status?: number;
  readonly cause?: unknown;

  constructor(
    errorCode: string,
    message: string,
    options: { retryable: boolean; status?: number; errorUri?: string; cause?: unknown },
  ) {
    super(errorCode, message, options.errorUri);
    this.name = "RefreshGrantError";
    this.retryable = options.retryable;
    this.status = options.status;
    this.cause = options.cause;
  }
}

/**
 * A device authorization request or a device token poll failed (RFC 8628),
 * or the poll loop stopped because the device code expired.
 *
 * `errorCode` is the server's `error` for an OAuth error response, and
 * `expired_token` when the loop stops at `expiresAt`. It is
 * `invalid_response` for a malformed response, for an HTTP error without an
 * OAuth error body, for a network error or timeout, and for a failed
 * discovery request.
 *
 * `retryable` is `true` for an HTTP 5xx or 429, whatever the error code.
 * Otherwise it is `false` for a code in `PERMANENT_ERROR_CODES` and for
 * `invalid_grant`, whose only recovery is a new device authorization
 * request, and `false` for an HTTP error without an OAuth error body. For a failed discovery
 * request it is `true` for a network error, a timeout, a 5xx, or a 429, and
 * `false` for any other status, a malformed document, or an issuer mismatch.
 * It is `true` for every other failure, including `authorization_pending`,
 * `slow_down`, and a network error. `cause` is the network error, the
 * timeout, or the discovery failure, when there is one.
 */
export class DeviceGrantError extends OAuthError {
  readonly retryable: boolean;
  readonly errorDescription?: string;
  readonly status?: number;
  readonly cause?: unknown;

  constructor(
    errorCode: string,
    options?: { errorDescription?: string; errorUri?: string; status?: number; retryable?: boolean; cause?: unknown },
  ) {
    super(errorCode, options?.errorDescription ?? `Device authorization grant failed: ${errorCode}`, options?.errorUri);
    this.name = "DeviceGrantError";
    const status = options?.status;
    const transientStatus = status !== undefined && (status >= 500 || status === 429);
    this.retryable =
      options?.retryable ?? (transientStatus || (!isPermanentErrorCode(errorCode) && errorCode !== "invalid_grant"));
    this.errorDescription = options?.errorDescription;
    this.status = status;
    this.cause = options?.cause;
  }
}

/**
 * `waitForDeviceToken` stopped on a network error, a timeout, an HTTP 5xx,
 * or an HTTP 429, and did not poll again. `interval` is the wait in seconds
 * the loop would have used before its next poll, including every
 * `slow_down` increase, and doubled after a network error or timeout
 * (RFC 8628 §3.5). `cause` is the original failure: the network error
 * or timeout, or the `DeviceGrantError` for the 5xx or 429 response.
 * `retryable` is always `true`.
 */
export class DevicePollError extends Error {
  readonly retryable = true;
  readonly interval: number;
  readonly cause: unknown;

  constructor(interval: number, cause: unknown) {
    super(`Device token poll failed (next interval ${interval}s): ${cause instanceof Error ? cause.message : String(cause)}`);
    this.name = "DevicePollError";
    this.interval = interval;
    this.cause = cause;
  }
}

/**
 * The `state` on the callback is absent or does not match the value stored at
 * the begin step (RFC 6749 §10.12). The flow is rejected before any token
 * request.
 */
export class StateMismatchError extends Error {
  constructor(message = "State mismatch in authorization callback: possible CSRF attack") {
    super(message);
    this.name = "StateMismatchError";
  }
}

export type ErrorDetail = {
  message: string;
  code?: string;
  description?: string;
  rawError?: string;
};

export type ResourceAccessErrorType =
  | "global_error"
  | "resource_error"
  | "missing_token";

export interface ResourceAccessErrorOptions {
  resource?: string;
  errorType?: ResourceAccessErrorType;
  availableResources?: readonly string[];
  errorDetails?: ErrorDetail | null;
}

export class ResourceAccessError extends Error {
  readonly resource?: string;
  readonly errorType?: ResourceAccessErrorType;
  readonly availableResources?: readonly string[];
  readonly errorDetails: ErrorDetail | null;

  constructor(message?: string, options?: ResourceAccessErrorOptions) {
    super(message ?? buildResourceAccessMessage(options));
    this.name = "ResourceAccessError";
    this.resource = options?.resource;
    this.errorType = options?.errorType;
    this.availableResources = options?.availableResources;
    this.errorDetails = options?.errorDetails ?? null;
  }
}

function buildResourceAccessMessage(options?: ResourceAccessErrorOptions): string {
  if (!options?.errorType) {
    return "Resource access denied or token not available";
  }
  const { resource, errorType, availableResources, errorDetails } = options;
  const label = resource ? `'${resource}'` : "resource";

  switch (errorType) {
    case "global_error": {
      const inner = errorDetails?.message ?? "Unknown global error";
      return `Cannot access resource ${label}: global authentication error. ${inner}`;
    }
    case "resource_error": {
      const inner = errorDetails?.message ?? "Unknown resource error";
      return `Cannot access resource ${label}: ${inner}`;
    }
    case "missing_token": {
      const list =
        availableResources && availableResources.length > 0
          ? ` Available: ${availableResources.join(", ")}.`
          : "";
      return `No access token available for resource ${label}.${list}`;
    }
  }
}

/**
 * A caller or server configuration problem that retrying will not fix: for
 * example, authorization-server metadata that lacks an endpoint the
 * operation needs. Mirrors Python's `ConfigError` and the Go and Ruby
 * `ConfigurationError`.
 */
export class ConfigurationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigurationError";
  }
}

export class AuthProviderConfigurationError extends ConfigurationError {
  constructor(message?: string) {
    super(message ?? "AuthProvider configuration is invalid");
    this.name = "AuthProviderConfigurationError";
  }
}

/**
 * Base class for JWKS key-resolution failures. Catch this to handle any JWKS
 * error, or a specific subclass for a single category. Mirrors the Python
 * `JWKSDiscoveryError` / `JWKSUriValidationError` taxonomy.
 */
export class JWKSError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "JWKSError";
  }
}

/** Discovery failed, or the metadata advertised no `jwks_uri`. */
export class JWKSDiscoveryError extends JWKSError {
  constructor(message: string) {
    super(message);
    this.name = "JWKSDiscoveryError";
  }
}

/** The discovered `jwks_uri` is cross-origin with the issuer (rejected before fetch). */
export class JWKSUriValidationError extends JWKSError {
  constructor(message: string) {
    super(message);
    this.name = "JWKSUriValidationError";
  }
}

/** The JWKS endpoint returned a non-2xx response. */
export class JWKSFetchError extends JWKSError {
  constructor(message: string) {
    super(message);
    this.name = "JWKSFetchError";
  }
}

/**
 * Token-endpoint discovery failed, or the metadata omitted `token_endpoint`.
 * `retryable` follows the base Retryability rule for metadata: `true` for a
 * transient failure (network error, timeout, HTTP 5xx or 429), `false` for a
 * deterministic one (other 4xx, issuer mismatch, malformed metadata, missing
 * `token_endpoint`). `cause` carries the underlying error when there is one.
 */
export class TokenEndpointDiscoveryError extends Error {
  readonly retryable: boolean;
  readonly cause?: unknown;

  constructor(message: string, options: { retryable: boolean; cause?: unknown }) {
    super(message);
    this.name = "TokenEndpointDiscoveryError";
    this.retryable = options.retryable;
    this.cause = options.cause;
  }
}

/**
 * A request could not reach its server, or the connection failed before a
 * complete response arrived. `cause` is the underlying transport error.
 * `retryable` is always `true`: a permanent failure surfaces as an HTTP or
 * protocol error, never as a network error.
 */
export class NetworkError extends Error {
  readonly retryable = true;
  readonly cause?: unknown;

  constructor(message: string, options?: { cause?: unknown }) {
    super(message);
    this.name = "NetworkError";
    this.cause = options?.cause;
  }
}

/**
 * The Connect error codes the Keycard agent answers `IssueToken` with, in the
 * snake_case spelling they carry on the wire. The list is not closed: any
 * other Connect code can arrive, and {@link AgentError.code} carries it as
 * sent. A code can have more than one cause; `message` tells them apart.
 */
export const AgentErrorCode = {
  /**
   * Issuance was refused: the human declined, the prompt expired or failed,
   * the authorization server rejected the exchange, the signed-in account
   * cannot read the zone's applications, or the `keycard agent` daemon has no
   * session for the requested org and zone. Do not retry automatically: the
   * agent remembers approvals but not declines, so a retry after a decline
   * prompts again, and a retry after the other causes fails the same way.
   */
  PERMISSION_DENIED: "permission_denied",
  /** The agent is bounding how often it interrupts the human. Back off. */
  RESOURCE_EXHAUSTED: "resource_exhausted",
  /**
   * The host has no way to ask a human, or the agent found no zone with the
   * configured id while resolving `appId`. Retrying will not help.
   */
  FAILED_PRECONDITION: "failed_precondition",
  /**
   * The developer must sign in, run the program under `keycard run`, or
   * repair the device key first; `message` names the remedy.
   */
  UNAUTHENTICATED: "unauthenticated",
  /** The declared `appId` names no application in the zone. */
  NOT_FOUND: "not_found",
  /**
   * Resolving the declared `appId` failed transiently: the management session
   * could not be renewed, or the application directory could not be reached.
   */
  UNAVAILABLE: "unavailable",
  /**
   * The request was malformed (for example a relative or non-ASCII resource),
   * `appId` was declared without an org or zone, or `appId` was declared to an
   * agent that cannot carry it.
   */
  INVALID_ARGUMENT: "invalid_argument",
  /** The authorization server returned no token, or the agent's audit log failed. */
  INTERNAL: "internal",
  /** The token exchange failed for a reason the agent does not classify. */
  UNKNOWN: "unknown",
} as const;
export type AgentErrorCode = (typeof AgentErrorCode)[keyof typeof AgentErrorCode];

/**
 * The local Keycard agent refused to issue a token. `code` is the Connect
 * error code (see {@link AgentErrorCode}); `message` is the agent's
 * explanation, which names the remedy where there is one. `message` is text
 * from the socket's peer: neutralize it before printing it to a terminal.
 * `retryable` is `true` for `resource_exhausted` and `unavailable` only.
 * Agent codes are not OAuth error codes, so {@link PERMANENT_ERROR_CODES}
 * does not apply to them.
 */
export class AgentError extends OAuthError {
  readonly retryable: boolean;

  constructor(code: AgentErrorCode | (string & {}), message: string) {
    super(code, message);
    this.name = "AgentError";
    this.retryable = code === AgentErrorCode.RESOURCE_EXHAUSTED || code === AgentErrorCode.UNAVAILABLE;
  }

  /** The Connect error code; the same value as `errorCode`. */
  get code(): AgentErrorCode | (string & {}) {
    return this.errorCode;
  }
}

/**
 * The local Keycard agent answered 200 with a response the SDK cannot use: a
 * body over 1 MiB or not JSON, a missing or empty token, a token carrying a
 * control character or a character above U+00FF, or an unparseable expiry. The message never includes the token.
 * `retryable` is always `false`.
 */
export class AgentResponseError extends OAuthError {
  readonly retryable = false;

  constructor(message: string) {
    super("invalid_response", message);
    this.name = "AgentResponseError";
  }
}

function findAgentError(error: unknown): AgentError | undefined {
  const seen = new Set<unknown>();
  while (error instanceof Error && !seen.has(error)) {
    if (error instanceof AgentError) return error;
    seen.add(error);
    error = (error as { cause?: unknown }).cause;
  }
  return undefined;
}

function hasAgentCode(error: unknown, code: AgentErrorCode): boolean {
  return findAgentError(error)?.code === code;
}

/**
 * Reports whether `error`, or an error on its `cause` chain, is an
 * {@link AgentError} with code `permission_denied`. That code also covers an
 * org and zone the `keycard agent` daemon has no session for, so a true
 * result is not proof that a human declined.
 */
export function isDeclined(error: unknown): boolean {
  return hasAgentCode(error, AgentErrorCode.PERMISSION_DENIED);
}

/** As {@link isDeclined}, for `resource_exhausted`. */
export function isRateLimited(error: unknown): boolean {
  return hasAgentCode(error, AgentErrorCode.RESOURCE_EXHAUSTED);
}

/**
 * As {@link isDeclined}, for `failed_precondition`. The agent also sends that
 * code when it finds no zone with the configured id, so read `message` before
 * telling the user no prompter is available.
 */
export function isPrompterUnavailable(error: unknown): boolean {
  return hasAgentCode(error, AgentErrorCode.FAILED_PRECONDITION);
}

/** As {@link isDeclined}, for `unauthenticated`. */
export function isAuthorizationRequired(error: unknown): boolean {
  return hasAgentCode(error, AgentErrorCode.UNAUTHENTICATED);
}

/** As {@link isDeclined}, for `not_found`. */
export function isApplicationNotFound(error: unknown): boolean {
  return hasAgentCode(error, AgentErrorCode.NOT_FOUND);
}

/** As {@link isDeclined}, for `unavailable`. */
export function isUnavailable(error: unknown): boolean {
  return hasAgentCode(error, AgentErrorCode.UNAVAILABLE);
}

/** The requested `kid` was not present in the fetched JWKS. */
export class JWKSKeyNotFoundError extends JWKSError {
  constructor(message: string) {
    super(message);
    this.name = "JWKSKeyNotFoundError";
  }
}
