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
