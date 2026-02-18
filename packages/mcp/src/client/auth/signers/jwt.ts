import { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import type { PrivateKeyring } from "@keycardai/oauth/keyring";
import { JWTSigner, type JWTClaims } from "@keycardai/oauth/jwt/signer";

export interface FullAuthInfo extends AuthInfo {
  userId: string;
  notBefore?: number;
  issuedAt?: number;
  uniqueId?: string;
}

export class JSONWebTokenSigner {
  #signer: JWTSigner;

  constructor(keyring: PrivateKeyring) {
    this.#signer = new JWTSigner(keyring);
  }

  async signToken(authInfo: Partial<FullAuthInfo>): Promise<string> {
    const claims: JWTClaims = {
      ...authInfo.extra,
      sub: authInfo.userId,
      aud: authInfo.resource?.toString(),
      client_id: authInfo.clientId,
      scope: authInfo.scopes?.join(' '),
      exp: authInfo.expiresAt,
      nbf: authInfo.notBefore,
      iat: authInfo.issuedAt,
      jti: authInfo.uniqueId,
    };

    return this.#signer.sign(claims);
  }
}
