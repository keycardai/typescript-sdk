import type { PrivateKeyring, IdentifiableKey } from "@keycardai/oauth/keyring";
import { JWTSigner } from "@keycardai/oauth/jwt/signer";
import type { TokenExchangeRequest } from "@keycardai/oauth/tokenExchange";
import type { ApplicationCredential } from "@keycardai/oauth/credentials";

export type { ApplicationCredential } from "@keycardai/oauth/credentials";

// =============================================================================
// WorkersClientSecret — Basic auth credential for Workers
// =============================================================================

export class WorkersClientSecret implements ApplicationCredential {
  #clientId: string;
  #clientSecret: string;

  constructor(clientId: string, clientSecret: string) {
    this.#clientId = clientId;
    this.#clientSecret = clientSecret;
  }

  getAuth(): { clientId: string; clientSecret: string } {
    return { clientId: this.#clientId, clientSecret: this.#clientSecret };
  }

  async prepareTokenExchangeRequest(
    subjectToken: string,
    resource: string,
  ): Promise<TokenExchangeRequest> {
    return {
      subjectToken,
      resource,
      subjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
    };
  }
}

// =============================================================================
// WorkersWebIdentity — private_key_jwt credential for Workers (RFC 7523)
// =============================================================================

export class WorkersWebIdentity implements ApplicationCredential {
  #privateKeyPem: string;
  #keyId: string;
  #cryptoKey?: CryptoKey;
  #publicJwk?: Record<string, unknown>;
  #importPromise?: Promise<void>;

  constructor(privateKeyPem: string, keyId?: string) {
    this.#privateKeyPem = privateKeyPem;
    this.#keyId = keyId ?? "worker-key";
  }

  getAuth(): null {
    return null;
  }

  async prepareTokenExchangeRequest(
    subjectToken: string,
    resource: string,
    options?: { tokenEndpoint?: string; authInfo?: Record<string, string> },
  ): Promise<TokenExchangeRequest> {
    await this.#ensureImported();

    const issuer = options?.authInfo?.resource_client_id ?? this.#keyId;
    const audience = options?.tokenEndpoint ?? issuer;

    const keyring = new WorkersPrivateKeyring(this.#cryptoKey!, this.#keyId, issuer);
    const signer = new JWTSigner(keyring);

    const now = Math.floor(Date.now() / 1000);
    const clientAssertion = await signer.sign({
      iss: issuer,
      sub: issuer,
      aud: audience,
      jti: crypto.randomUUID(),
      iat: now,
      exp: now + 300,
    });

    return {
      subjectToken,
      resource,
      subjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
      clientAssertionType: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      clientAssertion,
    };
  }

  /**
   * Returns the public JWKS for serving at /.well-known/jwks.json.
   * Must call after at least one prepareTokenExchangeRequest or importKey.
   */
  async getPublicJwks(): Promise<{ keys: Record<string, unknown>[] }> {
    await this.#ensureImported();
    return { keys: [this.#publicJwk!] };
  }

  async #ensureImported(): Promise<void> {
    if (this.#cryptoKey) return;
    if (!this.#importPromise) {
      this.#importPromise = this.#importKey();
    }
    return this.#importPromise;
  }

  async #importKey(): Promise<void> {
    // Strip PEM headers and decode
    const pemBody = this.#privateKeyPem
      .replace(/-----BEGIN (?:RSA )?PRIVATE KEY-----/g, "")
      .replace(/-----END (?:RSA )?PRIVATE KEY-----/g, "")
      .replace(/\s/g, "");

    const binaryDer = Uint8Array.from(atob(pemBody), (c) => c.charCodeAt(0));

    // Import as private key for signing
    this.#cryptoKey = await crypto.subtle.importKey(
      "pkcs8",
      binaryDer.buffer,
      { name: "RSASSA-PKCS1-v1_5", hash: { name: "SHA-256" } },
      true, // extractable — needed to export public JWK
      ["sign"],
    );

    // Export public key as JWK
    const jwk = await crypto.subtle.exportKey("jwk", this.#cryptoKey);
    this.#publicJwk = {
      kty: jwk.kty,
      n: jwk.n,
      e: jwk.e,
      kid: this.#keyId,
      alg: "RS256",
      use: "sig",
    };
  }
}

// =============================================================================
// WorkersPrivateKeyring — adapts a CryptoKey for JWTSigner
// =============================================================================

class WorkersPrivateKeyring implements PrivateKeyring {
  #key: CryptoKey;
  #kid: string;
  #issuer: string;

  constructor(key: CryptoKey, kid: string, issuer: string) {
    this.#key = key;
    this.#kid = kid;
    this.#issuer = issuer;
  }

  async key(_usage: string): Promise<IdentifiableKey> {
    return {
      key: this.#key,
      kid: this.#kid,
      issuer: this.#issuer,
    };
  }
}
