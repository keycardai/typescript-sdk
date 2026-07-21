import type { AuthInfo } from "../../../shared/auth.js";
import type { PrivateKeyring } from "@keycardai/oauth/keyring";
import { JWTSigner, type JWTClaims } from "@keycardai/oauth/jwt/signer";

export interface FullAuthInfo extends AuthInfo {
  userId: string;
  issuer?: string;
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
      // Set iss only when provided: the oauth signer falls back to the
      // keyring issuer for an absent iss, and callers that rely on that
      // fallback must not depend on how it treats an explicit undefined.
      ...(authInfo.issuer !== undefined ? { iss: authInfo.issuer } : {}),
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
