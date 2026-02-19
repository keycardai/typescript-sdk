import { PrivateKeyring } from "../keyring.js";
import base64url from "../base64url.js"

export interface JWTClaims {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  exp?: number;
  nbf?: number;
  iat?: number;
  jti?: string;
  scope?: string;
  client_id?: string;
  [key: string]: unknown;
}

export class JWTSigner {
  #privateKeyring: PrivateKeyring;

  constructor(keyring: PrivateKeyring) {
    this.#privateKeyring = keyring;
  }

  async sign(claims: JWTClaims): Promise<string> {
    const { key, kid, issuer }  = await this.#privateKeyring.key('sign');

    const jsonHeader = {
      alg: 'RS256',
      kid: kid
    };

    const resolvedClaims = { ...claims };
    if (issuer && !resolvedClaims.iss) {
      resolvedClaims.iss = issuer;
    }

    const header = btoau(JSON.stringify(jsonHeader));
    const payload = btoau(JSON.stringify(resolvedClaims));

    const input = `${header}.${payload}`;
    let signature = await crypto.subtle.sign(
      {
        name: 'RSASSA-PKCS1-v1_5',
      },
      key,
      stringToUint8Array(input)
    );

    return `${input}.${base64url.encode(signature)}`;
  }
}

function btoau(str: string): string {
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}

// TextEncoder.encode() always returns a Uint8Array backed by ArrayBuffer,
// but TS 5.7+ types .buffer as ArrayBufferLike (includes SharedArrayBuffer).
// The cast is safe and necessary for crypto.subtle.sign's BufferSource parameter.
function stringToUint8Array(str: string): ArrayBuffer {
  return new TextEncoder().encode(str).buffer as ArrayBuffer;
}
