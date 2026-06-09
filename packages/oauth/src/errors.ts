export class HTTPError extends Error {
  constructor(
    message: string
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

export class AuthProviderConfigurationError extends Error {
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

/** The requested `kid` was not present in the fetched JWKS. */
export class JWKSKeyNotFoundError extends JWKSError {
  constructor(message: string) {
    super(message);
    this.name = "JWKSKeyNotFoundError";
  }
}
