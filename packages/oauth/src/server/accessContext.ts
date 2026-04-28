import type { TokenResponse } from "../tokenExchange.js";
import { ResourceAccessError } from "../errors.js";

export type ErrorDetail = {
  message: string;
  code?: string;
  description?: string;
  rawError?: string;
};

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

  access(resource: string): TokenResponse {
    if (this.#error) {
      throw new ResourceAccessError();
    }
    if (this.#resourceErrors.has(resource)) {
      throw new ResourceAccessError();
    }
    const token = this.#accessTokens.get(resource);
    if (!token) {
      throw new ResourceAccessError();
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

  getResourceErrors(resource: string): ErrorDetail | null {
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
