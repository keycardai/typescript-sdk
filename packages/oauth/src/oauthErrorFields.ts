import type { OAuthErrorFields } from "./errors.js";

/**
 * Reads `error_description` and `reason` from an OAuth error body, keeping
 * each only when it is a string. `reason` passes through unchanged.
 */
export function oauthErrorFields(body: Record<string, unknown>): OAuthErrorFields {
  return {
    errorDescription: typeof body.error_description === "string" ? body.error_description : undefined,
    reason: typeof body.reason === "string" ? body.reason : undefined,
  };
}
