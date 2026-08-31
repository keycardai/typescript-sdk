/**
 * Errors this package raises into eve's own error channels.
 *
 * eve narrows connection authorization errors by `error.name` rather than by
 * `instanceof` (see `isConnectionAuthorizationRequiredError` in
 * `eve/connections`), and its `routeAuth` walk recognizes a rejection by the
 * `response` property carrying a `Response`. Both contracts are structural, so
 * this package satisfies them without importing eve at runtime: nothing here
 * loads eve code, which is what keeps the package usable from a Node 22
 * toolchain even though eve itself requires Node 24.
 */

/** eve's name for the authorization-required error. */
const AUTHORIZATION_REQUIRED_NAME = "ConnectionAuthorizationRequiredError";
/** eve's name for the authorization-failed error. */
const AUTHORIZATION_FAILED_NAME = "ConnectionAuthorizationFailedError";
/** eve's name for a route rejection carrying its own 401 response. */
const UNAUTHENTICATED_NAME = "UnauthenticatedError";

/**
 * Signals that the user must complete an authorization flow.
 *
 * Thrown from an interactive connection's `getToken`. eve emits
 * `authorization.required`, runs `startAuthorization`, and durably parks the
 * turn on its own callback webhook.
 */
export class AuthorizationRequiredError extends Error {
  readonly connectionName: string;

  constructor(connectionName: string, options?: { message?: string }) {
    super(options?.message ?? `Connection "${connectionName}" requires authorization.`);
    this.name = AUTHORIZATION_REQUIRED_NAME;
    this.connectionName = connectionName;
  }
}

/**
 * Signals that authorization failed.
 *
 * `reason` is the stable machine-readable code eve surfaces on the
 * `authorization.completed` event and on the failed tool result. `retryable`
 * is `false` for the cases a fresh consent page cannot fix, so eve stops
 * re-prompting: a run with no user principal, an expired subject token, or a
 * denied grant.
 */
export class AuthorizationFailedError extends Error {
  readonly connectionName: string;
  readonly reason?: string;
  readonly retryable: boolean;

  constructor(
    connectionName: string,
    options?: { message?: string; reason?: string; retryable?: boolean },
  ) {
    super(options?.message ?? `Connection "${connectionName}" authorization failed.`);
    this.name = AUTHORIZATION_FAILED_NAME;
    this.connectionName = connectionName;
    this.reason = options?.reason;
    this.retryable = options?.retryable ?? true;
  }
}

/** Reasons {@link AuthorizationFailedError} carries out of this package. */
export const FailureReason = Object.freeze({
  /**
   * eve's own reason for a user-scoped connection running without an
   * authenticated user. Raised here too, so a factory used outside eve's
   * principal resolution fails the same way instead of falling back to the
   * agent's authority.
   */
  PRINCIPAL_REQUIRED: "principal_required",
  /** The retained subject token is a JWT whose `exp` has passed. */
  SUBJECT_TOKEN_EXPIRED: "subject_token_expired",
  /** No subject token was retained for the principal of this turn. */
  SUBJECT_TOKEN_UNAVAILABLE: "subject_token_unavailable",
  /** The zone refused to issue a token for the connection's resource. */
  ACQUISITION_FAILED: "acquisition_failed",
  /** The user denied consent, or the provider returned an OAuth error. */
  ACCESS_DENIED: "access_denied",
  /** The callback did not carry the state journaled at the begin step. */
  INVALID_CALLBACK: "invalid_callback",
} as const);

/**
 * Rejects a route in eve's ordered auth walk with a structured 401.
 *
 * `routeAuth` returns the `response` of a thrown error that carries one, so
 * the walk stops here instead of continuing to a later, more permissive entry.
 */
export class RouteRejectedError extends Error {
  readonly response: Response;

  constructor(options?: { message?: string; code?: string; error?: string }) {
    super(options?.message ?? "Authorization is required for this route.");
    this.name = UNAUTHENTICATED_NAME;
    const challenge = options?.error
      ? `Bearer error="${options.error}"`
      : "Bearer";
    this.response = Response.json(
      {
        code: options?.code ?? "unauthorized",
        error: options?.message ?? "Authorization is required for this route.",
        ok: false,
      },
      {
        status: 401,
        headers: { "cache-control": "no-store", "www-authenticate": challenge },
      },
    );
  }
}
