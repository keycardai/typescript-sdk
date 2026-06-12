import type { TokenResponse } from "../tokenExchange.js";
import { ResourceAccessError, type ErrorDetail } from "../errors.js";

export type { ErrorDetail } from "../errors.js";

export type AccessContextStatus = "success" | "partial_error" | "error";

export class AccessContext {
  #accessTokens: Map<string, TokenResponse>;
  #resourceErrors: Map<string, ErrorDetail>;
  #error: ErrorDetail | null;

  constructor(accessTokens?: Record<string, TokenResponse>) {
    this.#accessTokens = new Map(accessTokens ? Object.entries(accessTokens) : []);
    this.#resourceErrors = new Map();
    this.#error = null;
  }

  setToken(resource: string, token: TokenResponse): void {
    this.#accessTokens.set(resource, token);
    this.#resourceErrors.delete(resource);
  }

  setBulkTokens(tokens: Record<string, TokenResponse>): void {
    for (const [resource, token] of Object.entries(tokens)) {
      this.#accessTokens.set(resource, token);
    }
  }

  setResourceError(resource: string, error: ErrorDetail): void {
    this.#resourceErrors.set(resource, error);
    this.#accessTokens.delete(resource);
  }

  setError(error: ErrorDetail): void {
    this.#error = error;
  }

  /**
   * Merge another context's tokens and errors into this one. Used when
   * multiple grants stack on the same request: later results accumulate
   * alongside earlier ones instead of replacing them. Per-resource entries
   * from `other` win on conflict; a global error on `other` overwrites
   * this context's global error.
   */
  merge(other: AccessContext): void {
    for (const [resource, token] of other.#accessTokens) {
      this.setToken(resource, token);
    }
    for (const [resource, error] of other.#resourceErrors) {
      this.setResourceError(resource, error);
    }
    if (other.#error) {
      this.#error = other.#error;
    }
  }

  access(resource: string): TokenResponse {
    if (this.#error) {
      throw new ResourceAccessError(undefined, {
        resource,
        errorType: "global_error",
        errorDetails: this.#error,
      });
    }
    const resourceError = this.#resourceErrors.get(resource);
    if (resourceError) {
      throw new ResourceAccessError(undefined, {
        resource,
        errorType: "resource_error",
        errorDetails: resourceError,
      });
    }
    const token = this.#accessTokens.get(resource);
    if (!token) {
      throw new ResourceAccessError(undefined, {
        resource,
        errorType: "missing_token",
        availableResources: [...this.#accessTokens.keys()],
      });
    }
    return token;
  }

  hasError(): boolean {
    return this.#error !== null;
  }

  hasResourceError(resource: string): boolean {
    return this.#resourceErrors.has(resource);
  }

  hasErrors(): boolean {
    return this.hasError() || this.#resourceErrors.size > 0;
  }

  getError(): ErrorDetail | null {
    return this.#error;
  }

  getResourceError(resource: string): ErrorDetail | null {
    return this.#resourceErrors.get(resource) ?? null;
  }

  getErrors(): { resources: Record<string, ErrorDetail>; error: ErrorDetail | null } {
    return {
      resources: Object.fromEntries(this.#resourceErrors),
      error: this.#error,
    };
  }

  getStatus(): AccessContextStatus {
    if (this.#error) return "error";
    if (this.#resourceErrors.size > 0) return "partial_error";
    return "success";
  }

  getSuccessfulResources(): string[] {
    return Array.from(this.#accessTokens.keys());
  }

  getFailedResources(): string[] {
    return Array.from(this.#resourceErrors.keys());
  }
}
