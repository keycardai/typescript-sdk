import type { AuthInfo, OAuthTokenVerifier } from "../../../shared/auth.js";
import { omitWhenPrinted } from "../../../shared/printed.js";
import type { OAuthKeyring } from "@keycardai/oauth/keyring";
import { JWTVerifier, type JWTVerifierOptions } from "@keycardai/oauth/jwt/verifier";
import { ConfigurationError } from "@keycardai/oauth/errors";
import { resolveResourceBinding, validateAudience, warnLegacy, zoneIssuers, type ResourceBindingOptions } from "../resourceBinding.js";

export class JWTOAuthTokenVerifier implements OAuthTokenVerifier {
  #verifier: OAuthTokenVerifier;

  constructor(keyring: OAuthKeyring, options: JWTVerifierOptions & ResourceBindingOptions) {
    const binding = resolveResourceBinding(options);
    validateAudience(binding, options.audiences);
    if (binding.mode === "perZone") {
      throw new ConfigurationError("Per-zone resource binding requires middleware with a request zoneResolver");
    }
    if (binding.mode === "shared" && typeof options.issuers !== "string") {
      throw new ConfigurationError("Shared discovery requires a single base issuer URL");
    }
    this.#verifier = makeJWTAccessTokenVerifier(keyring, {
      ...options,
      issuers: binding.mode === "shared"
        ? [...zoneIssuers(binding, options.issuers as string).values()]
        : options.issuers,
      audiences: binding.mode === "single" ? binding.identifier.value : options.audiences,
    });
    if (binding.mode === "legacy") {
      warnLegacy("JWTOAuthTokenVerifier", options.audiences);
    }
  }

  verifyAccessToken(token: string): Promise<AuthInfo> {
    return this.#verifier.verifyAccessToken(token);
  }
}

export function makeJWTAccessTokenVerifier(keyring: OAuthKeyring, options: JWTVerifierOptions): OAuthTokenVerifier {
  const verifier = new JWTVerifier(keyring, options);
  return { async verifyAccessToken(token) {
    const claims = await verifier.verify(token);

    const authInfo: AuthInfo = {
      token,
      // The verifier rejects missing `client_id` before we reach here, so the
      // cast is safe; the guard is gone.
      clientId: claims.client_id as string,
      resource: toResourceUrl(claims.aud),
      scopes: claims.scope ? claims.scope.split(" ") : [],
      expiresAt: claims.exp,
      aud: typeof claims.aud === "string" ? [claims.aud] : claims.aud ?? [],
      ...(claims.act !== null && typeof claims.act === "object" && !Array.isArray(claims.act)
        ? { act: claims.act as Record<string, unknown> }
        : {}),
    };
    return omitWhenPrinted(authInfo, "AuthInfo", ["token"]);
  } };
}

/**
 * Convert a JWT `aud` claim into the `AuthInfo.resource` URL.
 * Returns `undefined` when the claim is absent, empty, or not a valid URL
 * (opaque audience strings like `"my-api"` are valid per RFC 7519 but not
 * representable as a URL — we surface them via `AuthInfo.token` instead).
 */
function toResourceUrl(aud: string | string[] | undefined): URL | undefined {
  if (aud === undefined) return undefined;
  const primary = Array.isArray(aud) ? aud[0] : aud;
  if (!primary) return undefined;
  try {
    return new URL(primary);
  } catch {
    return undefined;
  }
}
