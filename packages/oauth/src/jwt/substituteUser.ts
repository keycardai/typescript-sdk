const SUBSTITUTE_USER_HEADER = { typ: "vnd.kc.su+jwt", alg: "none" };

/**
 * Build the substitute-user assertion sent as the `subject_token` of an
 * impersonation token exchange (RFC 8693, Keycard vendor extension).
 *
 * This is NOT a signed JWT and is NOT a general-purpose JWT builder. The
 * assertion's `alg: "none"` is intentional: the Keycard authorization server
 * trusts the call by validating the requesting client's credentials and the
 * vendor URN `urn:keycard:params:oauth:token-type:substitute-user`, not the
 * subject token's signature. Authority comes from the calling application's
 * client credentials plus the impersonation policy on the AS.
 *
 * For signing arbitrary JWTs, use `JWTSigner` from `@keycardai/oauth/jwt/signer`.
 */
export function buildSubstituteUserToken(identifier: string): string {
  if (!identifier) {
    throw new Error("identifier is required");
  }
  const header = btoau(JSON.stringify(SUBSTITUTE_USER_HEADER));
  const payload = btoau(JSON.stringify({ sub: identifier }));
  return `${header}.${payload}.`;
}

function btoau(str: string): string {
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}
