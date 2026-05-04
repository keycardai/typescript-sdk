export {
  HTTPError,
  BadRequestError,
  UnauthorizedError,
  OAuthError,
  InvalidTokenError,
  InsufficientScopeError,
  ResourceAccessError,
  AuthProviderConfigurationError,
} from "@keycardai/oauth/errors";

export class EKSWorkloadIdentityConfigurationError extends Error {
  constructor(message?: string) {
    super(message ?? "EKS workload identity configuration is invalid");
    this.name = "EKSWorkloadIdentityConfigurationError";
  }
}
