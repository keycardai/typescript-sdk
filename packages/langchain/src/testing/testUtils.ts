import { AccessContext, type TokenResponse } from "@keycardai/oauth";
import { runWithAccessContext } from "../accessStore.js";

export interface MockAccessContextOptions {
  /**
   * Served for every resource. Convenient, but it cannot catch a mistyped
   * resource URL in an `access(...)` call, since every lookup succeeds. Prefer
   * `resourceTokens` when the test should assert which resource a tool reads.
   */
  accessToken?: string;
  /** Per-resource tokens, keyed by resource URL. */
  resourceTokens?: Record<string, string>;
  /**
   * Per-resource failures, keyed by resource URL, as a grant failure would
   * record them.
   */
  resourceErrors?: Record<string, string>;
  /**
   * A global failure (no identity, unreachable zone). Takes precedence: no
   * resource tokens are served.
   */
  errorMessage?: string;
}

/**
 * Serve `access` to tools for the duration of `fn`.
 *
 * The full-control seam: build the `AccessContext` yourself (including partial
 * failures) and hand it over. {@link mockAccessContext} covers the common
 * cases. Generic over the return value, so a sync tool body and an async one
 * share one spelling.
 */
export function overrideAccessContext<T>(
  access: AccessContext,
  fn: (access: AccessContext) => T,
): T {
  return runWithAccessContext(access, () => fn(access));
}

/**
 * Serve a synthetic `AccessContext` to tools, with no exchange performed.
 */
export function mockAccessContext<T>(
  options: MockAccessContextOptions,
  fn: (access: AccessContext) => T,
): T {
  const access = new AnyResourceAccessContext(options.accessToken);

  if (options.errorMessage !== undefined) {
    access.setError({ message: options.errorMessage, code: "mock_error" });
  } else {
    for (const [resource, token] of Object.entries(options.resourceTokens ?? {})) {
      access.setToken(resource, bearer(token));
    }
    for (const [resource, message] of Object.entries(options.resourceErrors ?? {})) {
      access.setResourceError(resource, { message, code: "mock_resource_error" });
    }
  }

  return overrideAccessContext(access, fn);
}

function bearer(accessToken: string): TokenResponse {
  return { accessToken, tokenType: "Bearer" };
}

/**
 * An `AccessContext` that can serve one token for any resource.
 *
 * Only used when `mockAccessContext({ accessToken })` is given; with
 * `resourceTokens` the base class behavior applies unchanged.
 */
class AnyResourceAccessContext extends AccessContext {
  #defaultToken?: string;

  constructor(defaultToken?: string) {
    super();
    this.#defaultToken = defaultToken;
  }

  override access(resource: string): TokenResponse {
    if (
      this.#defaultToken !== undefined &&
      !this.hasErrors() &&
      !this.getSuccessfulResources().includes(resource)
    ) {
      return bearer(this.#defaultToken);
    }
    return super.access(resource);
  }
}
