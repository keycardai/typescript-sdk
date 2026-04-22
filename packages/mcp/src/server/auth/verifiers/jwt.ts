import { OAuthTokenVerifier } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import type { OAuthKeyring } from "@keycardai/oauth/keyring";
import { JWTVerifier, type JWTVerifierOptions } from "@keycardai/oauth/jwt/verifier";

export class JWTOAuthTokenVerifier implements OAuthTokenVerifier {
  #verifier: JWTVerifier;

  constructor(keyring: OAuthKeyring, options: JWTVerifierOptions) {
    this.#verifier = new JWTVerifier(keyring, options);
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    const claims = await this.#verifier.verify(token);

    return {
      token,
      // The verifier rejects missing `client_id` before we reach here, so the
      // cast is safe; the guard is gone.
      clientId: claims.client_id as string,
      resource: toResourceUrl(claims.aud),
      scopes: claims.scope ? claims.scope.split(" ") : [],
      expiresAt: claims.exp,
    };
  }
}

/**
 * Convert a JWT `aud` claim into the MCP SDK's `AuthInfo.resource` URL.
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
