/**
 * Reasons a connection auth provider fails with.
 *
 * The SDK surfaces a thrown provider as a failed turn (or a skipped
 * connection on an `optional` advertised connection) carrying the error's
 * message, so the message names the reason and the resource and never a
 * token.
 */
export const FailureReason = Object.freeze({
  /** A user-pattern connection ran with no Keycard user principal on the session. */
  PRINCIPAL_REQUIRED: "principal_required",
  /** No subject token was retained for the principal of this turn. */
  SUBJECT_TOKEN_UNAVAILABLE: "subject_token_unavailable",
  /** The retained subject token is a JWT whose `exp` has passed. */
  SUBJECT_TOKEN_EXPIRED: "subject_token_expired",
  /** The zone refused to issue a token for the connection's resource. */
  ACQUISITION_FAILED: "acquisition_failed",
  /** A `clientSecret` given as a `SecretRef` resolved to no value at call time. */
  CREDENTIAL_UNAVAILABLE: "credential_unavailable",
} as const);

export type FailureReasonCode = (typeof FailureReason)[keyof typeof FailureReason];

/** Thrown by a connection auth provider when it cannot return headers. */
export class ConnectionAuthError extends Error {
  readonly reason: FailureReasonCode;
  readonly connectionName: string;

  readonly cause?: unknown;

  constructor(
    reason: FailureReasonCode,
    connectionName: string,
    message: string,
    options?: { cause?: unknown },
  ) {
    super(`${reason}: ${message} (connection: ${connectionName})`);
    this.cause = options?.cause;
    this.name = "KeycardConnectionAuthError";
    this.reason = reason;
    this.connectionName = connectionName;
  }
}
