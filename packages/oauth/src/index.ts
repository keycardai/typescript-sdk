export type { OAuthKeyring, PrivateKeyring, IdentifiableKey, JWKSOAuthKeyringOptions } from "./keyring.js";
export { JWKSOAuthKeyring } from "./keyring.js";
export { default as base64url } from "./base64url.js";
export { fetchAuthorizationServerMetadata } from "./discovery.js";
export type { OAuthAuthorizationServerMetadata } from "./discovery.js";
export {
  HTTPError,
  BadRequestError,
  UnauthorizedError,
  TokenIntrospectionHTTPError,
  TokenRevocationHTTPError,
  OAuthError,
  MAX_RESPONSE_BODY_BYTES,
  ResponseBodyTooLargeError,
  InvalidTokenError,
  InsufficientScopeError,
  ResourceAccessError,
  ConfigurationError,
  CredentialDiscoveryError,
  AuthProviderConfigurationError,
  JWKSError,
  JWKSDiscoveryError,
  JWKSUriValidationError,
  JWKSFetchError,
  JWKSKeyNotFoundError,
  AuthorizationDeniedError,
  StateMismatchError,
  RefreshGrantError,
  TokenEndpointDiscoveryError,
  PERMANENT_ERROR_CODES,
  isPermanentErrorCode,
  DeviceGrantError,
  DevicePollError,
} from "./errors.js";
export type { CredentialDiscoveryReason } from "./errors.js";
export {
  CLIENT_ID_ENV_VAR,
  CLIENT_SECRET_ENV_VAR,
  WEB_IDENTITY_KEY_STORAGE_DIR_ENV_VAR,
  CREDENTIAL_TYPE_ENV_VAR,
  CLIENT_SECRET_TYPE,
  WORKLOAD_IDENTITY_TYPE,
  WEB_IDENTITY_TYPE,
  LEGACY_WORKLOAD_IDENTITY_TYPE,
  resolveCredentialType,
} from "./credentialDiscovery.js";
export type { CredentialEnvironment, CredentialType, ResolvedCredential } from "./credentialDiscovery.js";
export type { TokenEndpointCacheOptions } from "./tokenEndpoint.js";
export { JWTSigner } from "./jwt/signer.js";
export type { JWTClaims } from "./jwt/signer.js";
export { JWTVerifier } from "./jwt/verifier.js";
export { buildSubstituteUserToken } from "./jwt/substituteUser.js";
export { TokenExchangeClient, TokenType } from "./tokenExchange.js";
export type {
  TokenExchangeRequest,
  TokenResponse,
  TokenExchangeClientOptions,
  ExchangeOptions,
  ImpersonateRequest,
} from "./tokenExchange.js";
export { ClientCredentialsClient } from "./clientCredentials.js";
export type {
  ClientCredentialsRequest,
  ClientCredentialsClientOptions,
  RequestTokenOptions,
} from "./clientCredentials.js";
export type { ApplicationCredential, ClientAuthentication, ClientAuthenticator } from "./credentials.js";
export { createClientAuthentication, providesClientAuthentication } from "./credentials.js";
export { basicAuthorization } from "./basicAuthorization.js";
export { registerClient } from "./registration.js";
export type {
  ClientRegistrationRequest,
  ClientRegistrationResponse,
  RegisterClientOptions,
} from "./registration.js";
export { AccessContext, TokenVerifier, ClientSecret, discoverCredential } from "./server/index.js";
export type {
  ErrorDetail,
  AccessContextStatus,
  AccessToken,
  TokenVerifierOptions,
  ClientSecretCredentials,
  DiscoverCredentialOptions,
} from "./server/index.js";
export {
  generateCodeVerifier,
  generateCodeChallenge,
  generatePkcePair,
  exchangeAuthorizationCode,
  buildAuthorizeUrl,
  authenticate,
} from "./pkce.js";
export type {
  Pkce,
  ExchangeAuthorizationCodeOptions,
  AuthorizeUrlParams,
  AuthenticateOptions,
} from "./pkce.js";
export { beginAuthorization, completeAuthorization, refreshAuthorization } from "./webApp.js";
export type {
  BeginAuthorizationOptions,
  CompleteAuthorizationOptions,
  CompleteOptionsBase,
  CompleteWithCredentialOptions,
  RefreshAuthorizationOptions,
  RefreshOptionsBase,
  RefreshWithCredentialOptions,
  AuthorizationRedirect,
} from "./webApp.js";
export {
  DeviceAuthorizationClient,
  requestDeviceAuthorization,
  pollDeviceToken,
  waitForDeviceToken,
  systemClock,
} from "./deviceAuthorization.js";
export type {
  Clock,
  DeviceAuthorization,
  DeviceClientOptions,
  RequestDeviceAuthorizationOptions,
  PollDeviceTokenOptions,
  WaitForDeviceTokenOptions,
} from "./deviceAuthorization.js";
export { fetchUserInfo } from "./userinfo.js";
export type { UserInfoResponse, FetchUserInfoOptions } from "./userinfo.js";
export { revokeToken } from "./tokenRevocation.js";
export type { RevokeTokenOptions } from "./tokenRevocation.js";
export { introspectToken } from "./tokenIntrospection.js";
export type { IntrospectTokenOptions, TokenIntrospection } from "./tokenIntrospection.js";
export { resolveIssuerFromChallenge, authenticateFromChallenge } from "./challenge.js";
export type {
  AuthenticateFromChallengeOptions,
  ResolveIssuerFromChallengeOptions,
  ResolvedChallenge,
} from "./challenge.js";
