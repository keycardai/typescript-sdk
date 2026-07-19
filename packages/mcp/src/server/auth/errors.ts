export {
  HTTPError,
  BadRequestError,
  UnauthorizedError,
  OAuthError,
  InvalidTokenError,
  InsufficientScopeError,
  ResourceAccessError,
  AuthProviderConfigurationError,
  JWKSError,
  JWKSDiscoveryError,
  JWKSUriValidationError,
  JWKSFetchError,
  JWKSKeyNotFoundError,
} from "@keycardai/oauth/errors";

export class EKSWorkloadIdentityConfigurationError extends Error {
  constructor(message?: string) {
    super(message ?? "EKS workload identity configuration is invalid");
    this.name = "EKSWorkloadIdentityConfigurationError";
  }
}
