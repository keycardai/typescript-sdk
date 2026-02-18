import { z } from "zod";
import { fetchAuthorizationServerMetadata } from "./discovery.js";

export interface OAuthKeyring {
  key(issuer: string, kid: string): Promise<CryptoKey>
}

export type IdentifiableKey = {
  key: CryptoKey;
  issuer: string;
  kid: string;
};

export interface PrivateKeyring {
  key(usage: string): Promise<IdentifiableKey>
}


const JWKSchema = z.object({
  kty: z.string(),
  alg: z.string().optional(),
  use: z.string().optional(),
  kid: z.string().optional(),
});

const RSAJWKSchema = JWKSchema.extend({
  n: z.string(),
  e: z.string(),
});

const ECJWKSchema = JWKSchema.extend({
  crv: z.string(),
  x: z.string(),
  y: z.string(),
});

const JWKSetSchema = z.object({
  keys: z.array(z.union([RSAJWKSchema, ECJWKSchema])),
});

export class JWKSOAuthKeyring implements OAuthKeyring {

  async key(issuer: string, kid: string): Promise<CryptoKey> {
    const authorizationServer = await fetchAuthorizationServerMetadata(issuer);
    if (!authorizationServer.jwks_uri) {
      throw new Error(`No JSON Web Key Set available for "${issuer}"`);
    }
    const response = await fetch(authorizationServer.jwks_uri);
    if (!response.ok) {
      throw new Error(`Failed to fetch OAuth authorization server metadata for "${issuer}"`);
    }

    const json = await response.json();
    const jwkSet = JWKSetSchema.parse(json);
    const jwk = jwkSet.keys.find((jwk) => jwk.kid === kid);
    if (!jwk) {
      throw new Error(`Failed to find key "${kid}" of "${issuer}"`);
    }

    // TODO: make this more robust to uses and algs
    const key = await crypto.subtle.importKey(
      'jwk',
      jwk,
      {
        name: 'RSASSA-PKCS1-v1_5',
        hash: { name: 'SHA-256' },
      },
      true,
      ['verify']
    );
    return key;
  }
}
