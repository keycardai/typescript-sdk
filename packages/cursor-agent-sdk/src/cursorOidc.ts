import {
  WorkloadIdentityConfigurationError,
  WorkloadIdentityRuntimeError,
  type IdentityTokenSource,
} from "@keycardai/oauth/server";

/** Source identifier carried on workload identity errors from Cursor deployments. */
export const WORKLOAD_IDENTITY_SOURCE_CURSOR_DEPLOYMENT = "cursor-deployment";

/** OIDC token returned by Cursor's `getOidcToken` helper. */
export interface CursorOidcToken {
  readonly token: string;
  readonly expiresAt: Date;
}

/** Function matching `@grok/agent-sdk`'s `getOidcToken(audience)` signature. */
export type CursorOidcTokenFetcher = (audience: string) => Promise<CursorOidcToken>;

/** Options for {@link CursorDeploymentTokenSource}. */
export interface CursorDeploymentTokenSourceOptions {
  /** Exact audience declared in Cursor's `hosting.oidc.audiences`. */
  audience: string;
  /**
   * Optional override for Cursor's `getOidcToken` helper. When omitted,
   * `@grok/agent-sdk` is dynamically imported on the first token fetch.
   */
  getOidcToken?: CursorOidcTokenFetcher;
  /** @internal Override for loading `@grok/agent-sdk`, used in tests. */
  loadSdk?: () => Promise<{ getOidcToken?: unknown }>;
  /** Clock returning epoch milliseconds, used for expiry checks. Defaults to `Date.now`. */
  now?: () => number;
}

/**
 * Identity token source backed by Cursor's hosted deployment OIDC helper
 * (`getOidcToken` from `@grok/agent-sdk` 0.7.1 or later).
 *
 * Calls `getOidcToken(audience)` on every fetch at request time, never at
 * module load, and refuses any token at or past its reported `expiresAt`.
 */
export class CursorDeploymentTokenSource implements IdentityTokenSource {
  readonly #audience: string;
  readonly #getOidcToken?: CursorOidcTokenFetcher;
  readonly #loadSdk: () => Promise<{ getOidcToken?: unknown }>;
  readonly #now: () => number;

  constructor(options: CursorDeploymentTokenSourceOptions) {
    if (typeof options?.audience !== "string" || !options.audience.trim()) {
      throw new WorkloadIdentityConfigurationError("audience must not be empty", {
        source: WORKLOAD_IDENTITY_SOURCE_CURSOR_DEPLOYMENT,
      });
    }
    this.#audience = options.audience;
    this.#getOidcToken = options.getOidcToken;
    this.#loadSdk = options.loadSdk ?? (() => import("@grok/agent-sdk"));
    this.#now = options.now ?? Date.now;
  }

  async identityToken(): Promise<string> {
    const helper = await this.#resolveHelper();
    let result: CursorOidcToken;
    try {
      result = await helper(this.#audience);
    } catch (cause) {
      if (
        cause instanceof WorkloadIdentityConfigurationError ||
        cause instanceof WorkloadIdentityRuntimeError
      ) {
        throw cause;
      }
      if (isUndeclaredAudienceError(cause)) {
        throw new WorkloadIdentityConfigurationError(
          `Cursor OIDC audience "${this.#audience}" is not declared on this deployment; add it to hosting.oidc.audiences and redeploy`,
          { source: WORKLOAD_IDENTITY_SOURCE_CURSOR_DEPLOYMENT, cause },
        );
      }
      throw new WorkloadIdentityRuntimeError(
        `Cursor deployment OIDC helper failed: ${cause instanceof Error ? cause.message : String(cause)}`,
        {
          source: WORKLOAD_IDENTITY_SOURCE_CURSOR_DEPLOYMENT,
          cause,
          retryable: isRetryableHelperError(cause),
        },
      );
    }

    if (!result || typeof result.token !== "string" || !result.token.trim()) {
      throw new WorkloadIdentityRuntimeError(
        "Cursor deployment OIDC helper returned an empty token",
        { source: WORKLOAD_IDENTITY_SOURCE_CURSOR_DEPLOYMENT },
      );
    }
    if (!(result.expiresAt instanceof Date) || Number.isNaN(result.expiresAt.getTime())) {
      throw new WorkloadIdentityRuntimeError(
        "Cursor deployment OIDC helper returned an invalid expiresAt",
        { source: WORKLOAD_IDENTITY_SOURCE_CURSOR_DEPLOYMENT },
      );
    }
    if (result.expiresAt.getTime() <= this.#now()) {
      throw new WorkloadIdentityRuntimeError(
        "Cursor deployment OIDC helper returned an expired token",
        { source: WORKLOAD_IDENTITY_SOURCE_CURSOR_DEPLOYMENT },
      );
    }
    return result.token;
  }

  async #resolveHelper(): Promise<CursorOidcTokenFetcher> {
    if (this.#getOidcToken) return this.#getOidcToken;
    let mod: { getOidcToken?: unknown };
    try {
      mod = await this.#loadSdk();
    } catch (cause) {
      throw new WorkloadIdentityConfigurationError(
        "Cursor deployment OIDC requires @grok/agent-sdk 0.7.1 or later (failed to load getOidcToken helper)",
        { source: WORKLOAD_IDENTITY_SOURCE_CURSOR_DEPLOYMENT, cause },
      );
    }
    if (typeof mod?.getOidcToken !== "function") {
      throw new WorkloadIdentityConfigurationError(
        "Cursor deployment OIDC requires @grok/agent-sdk 0.7.1 or later (getOidcToken helper is missing)",
        { source: WORKLOAD_IDENTITY_SOURCE_CURSOR_DEPLOYMENT },
      );
    }
    return mod.getOidcToken as CursorOidcTokenFetcher;
  }
}

function isUndeclaredAudienceError(error: unknown): boolean {
  if (typeof error !== "object" || error === null) return false;
  const candidate = error as { code?: unknown; status?: unknown };
  return candidate.code === "failed" && candidate.status === 400;
}

function isRetryableHelperError(error: unknown): boolean {
  const seen = new Set<object>();
  while (typeof error === "object" && error !== null && !seen.has(error)) {
    seen.add(error);
    const { name, code, status, cause } = error as {
      name?: unknown;
      code?: unknown;
      status?: unknown;
      cause?: unknown;
    };
    if (typeof status === "number") return status === 429 || (status >= 500 && status < 600);
    if (code === "timeout" || code === "failed" || code === "rate_limited" || name === "TimeoutError") return true;
    if (typeof code === "string" && /^(EAI_AGAIN|ECONNABORTED|ECONNREFUSED|ECONNRESET|EHOSTUNREACH|ENETDOWN|ENETUNREACH|ENOTFOUND|EPIPE|ETIMEDOUT|UND_ERR_(CONNECT_TIMEOUT|HEADERS_TIMEOUT|BODY_TIMEOUT|SOCKET))$/.test(code)) return true;
    error = cause;
  }
  return false;
}
