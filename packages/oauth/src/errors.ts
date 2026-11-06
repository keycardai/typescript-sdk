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
 * with one of these codes is never retryable.
 */
const PERMANENT_ERROR_CODES: ReadonlySet<string> = new Set([
  "access_denied",
  "expired_token",
  "insufficient_authorization",
  "invalid_client",
]);

/** Reports whether `errorCode` is in the permanent table of the base Retryability rule. */
export function isPermanentErrorCode(errorCode: string): boolean {
  return PERMANENT_ERROR_CODES.has(errorCode);
}

/**
 * A refresh-token grant was not renewed. `errorCode` is the authorization
 * server's `error` when it returned one (`invalid_grant` means the refresh
 * token is expired, revoked, or was issued to another client, and the only
 * recovery is to authorize again), `invalid_response` otherwise. `retryable`
 * is `true` for a transport failure, HTTP 5xx, or 429, and `false` for every
 * other 4xx and for a code in the permanent table, such as `expired_token`.
 * `cause` holds the underlying error for a transport failure.
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
 * The authorization server refused a device authorization request or a
 * device token poll (RFC 8628), or the SDK ended the poll loop because the
 * device code expired. `errorCode` is the server's `error`, `expired_token`
 * when the loop stops at `expiresAt`, or `invalid_response` for a malformed
 * response. `retryable` is `false` for a code in the permanent table and for
 * `invalid_grant`, whose only recovery is a new device authorization
 * request. It is `true` for every other code, including
 * `authorization_pending` and `slow_down`.
 */
export class DeviceGrantError extends OAuthError {
  readonly retryable: boolean;
  readonly errorDescription?: string;
  readonly status?: number;

  constructor(
    errorCode: string,
    options?: { errorDescription?: string; errorUri?: string; status?: number },
  ) {
    super(errorCode, options?.errorDescription ?? `Device authorization grant failed: ${errorCode}`, options?.errorUri);
    this.name = "DeviceGrantError";
    this.retryable = !isPermanentErrorCode(errorCode) && errorCode !== "invalid_grant";
    this.errorDescription = options?.errorDescription;
    this.status = options?.status;
  }
}

/**
 * The device token poll loop stopped on a network error, an HTTP 5xx, or an
 * HTTP 429. It does not poll again. `cause` is the original failure: the
 * fetch error, an `HTTPError`, or a `DeviceGrantError` when the 5xx or 429
 * response had an OAuth error body. `interval` is the wait in seconds the
 * loop would have used before its next poll, including every `slow_down`
 * increase. To resume, call `waitForDeviceToken` again with the same
 * `DeviceAuthorization` and this `interval` before `expiresAt`. After a
 * timeout, wait longer than `interval` before resuming (RFC 8628 §3.5).
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

/** The requested `kid` was not present in the fetched JWKS. */
export class JWKSKeyNotFoundError extends JWKSError {
  constructor(message: string) {
    super(message);
    this.name = "JWKSKeyNotFoundError";
  }
}
