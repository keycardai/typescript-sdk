import { OAuthKeyring } from "../keyring.js";
import { InvalidTokenError } from "../errors.js";
import base64url from "../base64url.js";
import type { JWTClaims } from "./signer.js";

export class JWTVerifier {
  #keyring: OAuthKeyring;

  constructor(keyring: OAuthKeyring) {
    this.#keyring = keyring;
  }

  async verify(token: string): Promise<JWTClaims> {
    const [header, payload, signature, ...rest] = token.split('.');

    const jsonHeader = JSON.parse(autob(header));
    const jsonPayload: JWTClaims = JSON.parse(autob(payload));

    if (!jsonPayload.iss) {
      throw new InvalidTokenError("JWT missing issuer (iss) claim");
    }

    const key = await this.#keyring.key(jsonPayload.iss, jsonHeader.kid);

    const verified = await crypto.subtle.verify(
      {
        name: 'RSASSA-PKCS1-v1_5',
        hash: { name: 'SHA-256' },
      },
      key,
      base64url.decode(signature),
      new TextEncoder().encode(`${header}.${payload}`)
    );
    if (!verified) {
      throw new InvalidTokenError("Invalid signature");
    }

    return jsonPayload;
  }
}

function autob(data: string): string {
  return atob(data.replace(/-/g, '+').replace(/_/g, '/'));
}
