import { OAuthTokenVerifier } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import type { OAuthKeyring } from "@keycardai/oauth/keyring";
import { JWTVerifier, type JWTVerifierOptions } from "@keycardai/oauth/jwt/verifier";

export type JWTOAuthTokenVerifierOptions = JWTVerifierOptions;

export class JWTOAuthTokenVerifier implements OAuthTokenVerifier {
  #verifier: JWTVerifier;

  constructor(keyring: OAuthKeyring, options: JWTOAuthTokenVerifierOptions) {
    this.#verifier = new JWTVerifier(keyring, options);
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    const claims = await this.#verifier.verify(token);

    return {
      token,
      clientId: claims.client_id ?? "",
      resource: claims.aud
        ? new URL(Array.isArray(claims.aud) ? claims.aud[0] : claims.aud)
        : undefined,
      scopes: claims.scope ? claims.scope.split(" ") : [],
      expiresAt: claims.exp,
    };
  }
}
