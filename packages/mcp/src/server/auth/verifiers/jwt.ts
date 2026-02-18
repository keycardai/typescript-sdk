import { OAuthTokenVerifier } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import type { OAuthKeyring } from "@keycardai/oauth/keyring";
import { JWTVerifier } from "@keycardai/oauth/jwt/verifier";
import { InvalidTokenError } from "../errors.js";

export class JWTOAuthTokenVerifier implements OAuthTokenVerifier {
  #verifier: JWTVerifier;

  constructor(keyring: OAuthKeyring) {
    this.#verifier = new JWTVerifier(keyring);
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    const claims = await this.#verifier.verify(token);

    return {
      token,
      clientId: claims.client_id ?? '',
      resource: claims.aud ? new URL(claims.aud) : undefined,
      scopes: claims.scope ? claims.scope.split(' ') : [],
      expiresAt: claims.exp,
    };
  }
}
