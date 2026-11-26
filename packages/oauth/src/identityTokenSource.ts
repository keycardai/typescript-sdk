import { HTTPError } from "./errors.js";

export const WORKLOAD_IDENTITY_SOURCE_CUSTOM = "custom";

/**
 * A workload identity credential or token source is misconfigured.
 * `source` identifies the token source, and `cause` preserves the underlying error.
 */
export class WorkloadIdentityConfigurationError extends Error {
  readonly source?: string;
  readonly cause?: unknown;

  constructor(message: string, options?: { source?: string; cause?: unknown }) {
    super(message);
    this.name = "WorkloadIdentityConfigurationError";
    this.source = options?.source;
    this.cause = options?.cause;
  }
}

/**
 * A workload identity token cannot be obtained at request time.
 * `source` identifies the token source, and `cause` preserves the underlying error.
 * `retryable` indicates that the source classified the failure as transient.
 */
export class WorkloadIdentityRuntimeError extends Error {
  readonly source?: string;
  readonly cause?: unknown;
  readonly retryable: boolean;

  constructor(message: string, options?: { source?: string; cause?: unknown; retryable?: boolean }) {
    super(message);
    this.name = "WorkloadIdentityRuntimeError";
    this.source = options?.source;
    this.cause = options?.cause;
    this.retryable = options?.retryable ?? false;
  }
}

/**
 * Supplies the current platform-signed OIDC token for a client assertion or
 * an actor token. The client calls the source for each exchange that needs it.
 */
export interface IdentityTokenSource {
  identityToken(): Promise<string>;
}

/** A bare function accepted anywhere an IdentityTokenSource is. */
export type IdentityTokenFetcher = () => Promise<string> | string;

export function validateIdentityTokenSource(source: unknown): void {
  if (source == null) {
    throw new WorkloadIdentityConfigurationError("identity token source must not be null");
  }
  if (typeof source !== "function" && typeof (source as IdentityTokenSource).identityToken !== "function") {
    throw new WorkloadIdentityConfigurationError(
      "identity token source must provide identityToken() or be a function",
    );
  }
}

const transportErrorCodes = new Set([
  "EAI_AGAIN", "ECONNABORTED", "ECONNREFUSED", "ECONNRESET", "EHOSTUNREACH",
  "ENETDOWN", "ENETUNREACH", "ENOTFOUND", "EPIPE", "ETIMEDOUT",
  "UND_ERR_CONNECT_TIMEOUT", "UND_ERR_HEADERS_TIMEOUT", "UND_ERR_BODY_TIMEOUT", "UND_ERR_SOCKET",
]);

export function isRetryableSourceStatus(status: number): boolean {
  return status === 429 || (status >= 500 && status < 600);
}

export function isRetryableSourceFailure(cause: unknown): boolean {
  const seen = new Set<object>();
  while (cause && typeof cause === "object" && !seen.has(cause)) {
    seen.add(cause);
    const { name, code, status, cause: nested } = cause as {
      name?: unknown;
      code?: unknown;
      status?: unknown;
      cause?: unknown;
    };
    if (typeof status === "number") return isRetryableSourceStatus(status);
    if (name === "TimeoutError" || (typeof code === "string" && transportErrorCodes.has(code))) return true;
    if (cause instanceof HTTPError && nested === undefined) return true;
    cause = nested;
  }
  return false;
}

export async function fetchIdentityToken(
  source: IdentityTokenSource | IdentityTokenFetcher,
  receiver?: object,
): Promise<string> {
  let token: string;
  try {
    token = typeof source === "function" ? await Reflect.apply(source, receiver, []) : await source.identityToken();
  } catch (error) {
    if (
      error instanceof WorkloadIdentityConfigurationError ||
      error instanceof WorkloadIdentityRuntimeError
    ) {
      throw error;
    }
    throw new WorkloadIdentityRuntimeError("Error fetching identity token", {
      source: WORKLOAD_IDENTITY_SOURCE_CUSTOM,
      cause: error,
    });
  }
  if (typeof token !== "string" || !token.trim()) {
    throw new WorkloadIdentityRuntimeError("Identity token source returned an empty token", {
      source: WORKLOAD_IDENTITY_SOURCE_CUSTOM,
    });
  }
  return token;
}
