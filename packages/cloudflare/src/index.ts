// Auth
export { verifyBearerToken, isAuthError } from "./auth.js";

// Metadata
export { handleMetadataRequest } from "./metadata.js";

// Credentials
export {
  WorkersClientSecret,
  WorkersWebIdentity,
} from "./credentials.js";
export type { ApplicationCredential } from "./credentials.js";

// Token cache
export { IsolateSafeTokenCache } from "./tokenCache.js";
export type { IsolateSafeTokenCacheOptions } from "./tokenCache.js";

// Worker
export { createKeycardWorker, resolveCredential } from "./worker.js";

// Types
export type {
  KeycardEnv,
  AuthInfo,
  AuthenticatedFetchHandler,
  KeycardWorkerOptions,
  MetadataOptions,
  BearerAuthOptions,
} from "./types.js";

// Errors (re-exported from @keycardai/oauth)
export {
  BadRequestError,
  UnauthorizedError,
  InvalidTokenError,
  InsufficientScopeError,
  OAuthError,
} from "./errors.js";
