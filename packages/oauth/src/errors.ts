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

export class ResourceAccessError extends Error {
  constructor(message?: string) {
    super(message ?? "Resource access denied or token not available");
    this.name = "ResourceAccessError";
  }
}

export class AuthProviderConfigurationError extends Error {
  constructor(message?: string) {
    super(message ?? "AuthProvider configuration is invalid");
    this.name = "AuthProviderConfigurationError";
  }
}
