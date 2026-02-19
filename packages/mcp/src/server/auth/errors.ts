export { HTTPError, BadRequestError, UnauthorizedError, OAuthError, InvalidTokenError, InsufficientScopeError } from "@keycardai/oauth/errors";

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

export class EKSWorkloadIdentityConfigurationError extends Error {
  constructor(message?: string) {
    super(message ?? "EKS workload identity configuration is invalid");
    this.name = "EKSWorkloadIdentityConfigurationError";
  }
}
